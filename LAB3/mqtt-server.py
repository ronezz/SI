import paho.mqtt.client as mqtt
import doubleratchet as dr
import sys
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

NAME = "ancr"
PEER = "mgestal"

MQTT_SERVER = '18.101.140.151'
MQTT_USER = "sinf"
MQTT_PASSWORD = "sinf2025"
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60

PUBLISH_TOPIC = f"{NAME}.out"
SUBSCRIBE_TOPIC = f"{PEER}.in"

private_key, public_key = dr.generate_dh_key_pair()
root_key = b'\x00' * 16

other_public_key = None
message_count = 0


def clear_line():
    sys.stdout.write('\r\033[K')
    sys.stdout.flush()


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT server")
        client.subscribe(SUBSCRIBE_TOPIC)
    else:
        print(f"Connection error: {rc}")


#While listening...
def on_message(client, userdata, msg):
    global other_public_key
    try:
        parts = msg.payload.decode().split(":")

        # Initial key exchange
        if parts[0] == "start":
            other_public_key = x25519.X25519PublicKey.from_public_bytes(
                bytes.fromhex(parts[1])
            )
            print(f"{PEER} public key received")

        # Encrypted message
        else:
            public_key_hex, nonce_hex, ciphertext_hex = parts
            received_public_key = x25519.X25519PublicKey.from_public_bytes(
                bytes.fromhex(public_key_hex)
            )

            if other_public_key != received_public_key:
                other_public_key = received_public_key
                print("New public key received")

            derived_key = dr.dh_ratchet(private_key, other_public_key)
            key = dr.symmetric_ratchet(derived_key, root_key)

            plaintext = dr.decrypt(
                key,
                bytes.fromhex(nonce_hex),
                bytes.fromhex(ciphertext_hex)
            )
            
            clear_line()
            print(f"{PEER}: {plaintext.decode()}")
            
            sys.stdout.write("You: ")
            sys.stdout.flush()

    except Exception as e:
        print(f"Error processing message: {e}")


def send_message(client, message):
    global private_key, public_key, message_count

    if other_public_key is None:
        print(f"Waiting for {PEER} public key...")
        return

    if message_count >= 2:
        private_key, public_key = dr.generate_dh_key_pair()
        message_count = 0
        print("New DH key pair generated")

    derived_key = dr.dh_ratchet(private_key, other_public_key)
    key = dr.symmetric_ratchet(derived_key, root_key)
    nonce, ciphertext = dr.encrypt(key, message.encode())

    public_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

    payload = f"{public_hex}:{nonce.hex()}:{ciphertext.hex()}"
    client.publish(PUBLISH_TOPIC, payload)

    clear_line()
    
    sys.stdout.write("You: ")
    sys.stdout.flush()
    
    message_count += 1


def main():
    client = mqtt.Client()
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message

    print("Connecting to MQTT server...")
    client.connect(MQTT_SERVER, MQTT_PORT, MQTT_KEEPALIVE)
    client.loop_start()

    # Send initial public key
    public_hex = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    client.publish(PUBLISH_TOPIC, f"start:{public_hex}")
    print(f"Public key sent to {PEER}")
    
    # Mostrar prompt inicial
    sys.stdout.write("You: ")
    sys.stdout.flush()

    while True:
        msg = input()
        if msg.lower() == "quit":
            break
        send_message(client, msg)

    client.loop_stop()
    client.disconnect()
    print("Disconnected")


if __name__ == "__main__":
    main()
