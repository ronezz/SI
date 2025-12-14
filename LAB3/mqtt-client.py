# mqtt client
import paho.mqtt.client as mqtt
import doubleratchet as dr
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

MQTT_SERVER = '18.101.140.151'
MQTT_USER = "sinf"
MQTT_PASSWORD = "sinf2025"
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60
MQTT_TOPIC_IN = "hnf.in"
MQTT_TOPIC_OUT = "hnf.out"


private_key, public_key = dr.generate_dh_key_pair()
root_key = b'\x00' * 16  
other_public_key = None
message_count = 0


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Connected to MQTT server")
        client.subscribe(MQTT_TOPIC_IN)
    else:
        print(f"Connection error: {rc}")

# While listening...
def on_message(client, userdata, msg):
    global other_public_key, message_count
    try:
        msg_payload = msg.payload.decode('utf-8')
        parts = msg_payload.split(':')
        
        print(f"Message received ({len(parts)} parts)")
        
        # First message
        if parts[0] == 'start':
            # Receive public key from Bob
            public_key_bytes = bytes.fromhex(parts[1])
            other_public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
            print("Bob public key received")

        else:
            if len(parts) == 3:
                public_key_hex, nonce_hex, ciphertext_hex = parts
                
                public_key_bytes = bytes.fromhex(public_key_hex)
                nonce = bytes.fromhex(nonce_hex)
                ciphertext = bytes.fromhex(ciphertext_hex)
                
                received_public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
                if other_public_key != received_public_key:
                    other_public_key = received_public_key
                    print("New public key received")
                
                derived_key = dr.dh_ratchet(private_key, other_public_key)
                key = dr.symmetric_ratchet(derived_key, root_key)
                plaintext = dr.decrypt(key, nonce, ciphertext)
                
                print(f"Bob: {plaintext.decode('utf-8')}")
            else:
                print(f"Invalid message format: {len(parts)} parts")
                
    except Exception as e:
        print(f"Error processing message: {e}")

def send_message(client, message):
    global private_key, public_key, message_count
    
    if other_public_key is None:
        print("Wait to receive Bob public key first")
        return
    
    try:
        # Generate a new DH pair every 2 messages
        if message_count >= 2:
            private_key, public_key = dr.generate_dh_key_pair()
            message_count = 0
            print("New DH key pair generated")
        
        # Ratchet y cifrado
        derived_key = dr.dh_ratchet(private_key, other_public_key)
        key = dr.symmetric_ratchet(derived_key, root_key)
        nonce, ciphertext = dr.encrypt(key, message.encode('utf-8'))
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        public_hex = public_bytes.hex()
        nonce_hex = nonce.hex()
        ciphertext_hex = ciphertext.hex()
        
        msg_payload = f"{public_hex}:{nonce_hex}:{ciphertext_hex}"
        client.publish(MQTT_TOPIC_OUT, msg_payload)
        print(f"Alice: {message}")
        
        message_count += 1
        
    except Exception as e:
        print(f"Error sending message: {e}")

def main():
    client = mqtt.Client()
    client.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    client.on_connect = on_connect
    client.on_message = on_message
    
    try:
        print("Connecting to MQTT server...")
        client.connect(MQTT_SERVER, MQTT_PORT, MQTT_KEEPALIVE)
        client.loop_start()
        
        # Send public key
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        public_hex = public_bytes.hex()
        client.publish(MQTT_TOPIC_OUT, f"start:{public_hex}")
        print("Public key sent to Bob")
        
        # Bucle principal
        while True:
            message = input("\nEnter message: ")
            if message.lower() == 'quit':
                break
            send_message(client, message)
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.loop_stop()
        client.disconnect()
        print("Disconnected")

if __name__ == "__main__":
    main()
