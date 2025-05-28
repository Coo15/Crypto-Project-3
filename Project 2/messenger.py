from lib import (
    gen_random_salt,
    generate_eg,
    compute_dh,
    verify_with_ecdsa,
    hmac_to_aes_key,
    hkdf,
    encrypt_with_gcm,
    decrypt_with_gcm,
    gov_encryption_data_str
)

# Helper: a simple ratchet update function using a fixed salt.
def ratchet_update(chain_key: bytes) -> tuple[bytes, bytes]:
    # hkdf returns a tuple; we use first output as message key and second as new chain key.
    return hkdf(chain_key, salt=b"ratchet", info_str="messenger_ratchet")

class MessengerClient:
    def __init__(self, cert_authority_public_key: bytes, gov_public_key: bytes):
        """
        The certificate authority public key is used to verify the authenticity and integrity
        of certificates of other users.
        """
        self.ca_public_key = cert_authority_public_key
        self.gov_public_key = gov_public_key
        self.conns = {}   # conversation state, keyed by other party's username
        self.certs = {}   # certificates of other users
        self.own_certificate = None
        self.own_private_key = None
        self.username = None

    def generate_certificate(self, username: str) -> dict:
        """
        Generate a certificate to be stored with the certificate authority.
        The certificate must contain the field "username" and our ElGamal public key.
        """
        self.username = username
        keys = generate_eg()
        self.own_private_key = keys["private"]
        certificate = {
            "username": username,
            "public_key": keys["public"]
        }
        self.own_certificate = certificate
        return certificate

    def receive_certificate(self, certificate: dict, signature: bytes) -> None:
        """
        Receive and store another user's certificate after verifying its signature.
        If verification fails, raise a ValueError with message "Tampering detected!".
        """
        cert_str = str(certificate)
        if not verify_with_ecdsa(self.ca_public_key, cert_str, signature):
            raise ValueError("Tampering detected!")
        # Store the certificate keyed by the username.
        self.certs[certificate["username"]] = certificate

    def _initiate_outgoing_convo(self, recipient: str) -> None:
        """
        Initialize conversation state for sending a message.
        For an outgoing conversation, we compute a shared secret with the recipient's public key.
        We then derive a send chain and a receive chain as follows:
          (send_chain, recv_chain) = hkdf(shared, salt=b"init", info_str="messenger")
        """
        if recipient not in self.certs:
            raise Exception(f"No certificate for user {recipient} found!")
        their_pub = self.certs[recipient]["public_key"]
        shared = compute_dh(self.own_private_key, their_pub)
        # For the sender, use the first key as the sending chain and the second as the receiving chain.
        send_chain, recv_chain = hkdf(shared, salt=b"init", info_str="messenger")
        self.conns[recipient] = {
            "send_chain": send_chain,
            "send_counter": 0,
            "recv_chain": recv_chain,
            "recv_counter": 0,
            "skipped": {},      # for storing skipped (out-of-order) message keys
            "received": set()   # to detect replays (stores processed msg numbers)
        }

    def _initiate_incoming_convo(self, sender: str) -> None:
        """
        Initialize conversation state for receiving a message.
        For an incoming conversation, roles are reversed.
        We compute the shared secret with the sender's public key and derive:
          (recv_chain, send_chain) = hkdf(shared, salt=b"init", info_str="messenger")
        """
        if sender not in self.certs:
            raise Exception(f"No certificate for user {sender} found!")
        their_pub = self.certs[sender]["public_key"]
        shared = compute_dh(self.own_private_key, their_pub)
        # For the receiver, use the first key as the receiving chain.
        recv_chain, send_chain = hkdf(shared, salt=b"init", info_str="messenger")
        self.conns[sender] = {
            "send_chain": send_chain,
            "send_counter": 0,
            "recv_chain": recv_chain,
            "recv_counter": 0,
            "skipped": {},
            "received": set()
        }

    def send_message(self, name: str, plaintext: str) -> tuple[dict, tuple[bytes, bytes]]:
        """
        Generate the message to be sent to another user.
        This function:
         - Initializes a conversation (if needed) with a DH exchange.
         - Uses a ratchet update to derive a new message key and updates the sending chain.
         - Prepares a header containing:
              sender, recipient, message number,
              government encryption fields ("v_gov", "c_gov", "iv_gov"),
              and a randomly generated "receiver_iv" for message encryption.
         - Encrypts the plaintext using AES-GCM with the message key (using the header as AAD).
        """
        # Initialize conversation state if needed.
        if name not in self.conns:
            self._initiate_outgoing_convo(name)
        state = self.conns[name]
        msg_num = state["send_counter"]
        # Perform ratchet update: derive message_key and update send_chain.
        message_key, new_send_chain = ratchet_update(state["send_chain"])
        # Prepare government encryption of the message_key.
        gov_ephemeral = generate_eg()
        gov_shared = compute_dh(gov_ephemeral["private"], self.gov_public_key)
        gov_aes_key = hmac_to_aes_key(gov_shared, gov_encryption_data_str)
        iv_gov = gen_random_salt()
        # Encrypt the message_key directly (as bytes) without conversion.
        c_gov = encrypt_with_gcm(gov_aes_key, message_key, iv_gov)
        # Generate an IV for the message encryption.
        receiver_iv = gen_random_salt()
        # Assemble header (include sender and intended recipient).
        header = {
            "sender": self.username,
            "recipient": name,
            "msg_num": msg_num,
            "v_gov": gov_ephemeral["public"],
            "c_gov": c_gov,
            "iv_gov": iv_gov,
            "receiver_iv": receiver_iv
        }
        auth_data = str(header)
        ciphertext = encrypt_with_gcm(message_key, plaintext, receiver_iv, authenticated_data=auth_data)
        # Update sending state.
        state["send_chain"] = new_send_chain
        state["send_counter"] += 1
        return header, ciphertext

    def receive_message(self, name: str, message: tuple[dict, tuple[bytes, bytes]]) -> str:
        """
        Decrypt a message received from another user.
        This function:
         - Checks that the message header indicates the message is intended for this user.
         - If no conversation state exists for the sender, it initializes one (with roles reversed).
         - It then uses the message number in the header to determine whether to use a fresh ratchet update
           or to retrieve a previously skipped key.
         - If a message replay is detected (same message number processed twice), an exception is raised.
         - Finally, the ciphertext is decrypted using the derived message key.
        """
        header, ciphertext = message
        # Check that this message is intended for us.
        if header.get("recipient") != self.username:
            raise Exception("Message not intended for this recipient!")
        sender = header.get("sender")
        if sender is None:
            raise Exception("Header missing sender!")
        # If no conversation state exists for the sender, initialize it (incoming role).
        if sender not in self.conns:
            self._initiate_incoming_convo(sender)
        state = self.conns[sender]
        msg_num = header.get("msg_num")
        if msg_num is None:
            raise Exception("Header missing msg_num!")
        # Check for replay.
        if msg_num in state["received"]:
            raise Exception("Replay attack detected!")
        # If the message key for this msg_num was already skipped, use it.
        if msg_num in state["skipped"]:
            message_key = state["skipped"].pop(msg_num)
        else:
            # If the header's msg_num is greater than our current receive counter,
            # derive and store skipped keys until reaching the current one.
            while state["recv_counter"] < msg_num:
                key, new_chain = ratchet_update(state["recv_chain"])
                state["skipped"][state["recv_counter"]] = key
                state["recv_chain"] = new_chain
                state["recv_counter"] += 1
            # Now, derive the key for the current message.
            message_key, new_chain = ratchet_update(state["recv_chain"])
            state["recv_chain"] = new_chain
            state["recv_counter"] += 1
        # Mark this message number as processed.
        state["received"].add(msg_num)
        auth_data = str(header)
        plaintext = decrypt_with_gcm(message_key, ciphertext, header["receiver_iv"], authenticated_data=auth_data)
        return plaintext
