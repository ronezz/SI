from paho.mqtt import client as paho_mqtt
import tor

MQTT_SERVER = "18.101.140.151"
MQTT_USER = "sinf"
MQTT_PASSWORD = "sinf2025"
MQTT_PORT = 1883
MQTT_TOPIC = "ancr"
MQTT_KEEPALIVE = 60

def mqtt_client(server, port, topic, user, password, keepalive):
    client = paho_mqtt.Client()
    client.username_pw_set(user, password)
    client.connect(server, port, keepalive)
    client.subscribe(topic)
    return client


# Create MQTT Client
client = mqtt_client(MQTT_SERVER, MQTT_PORT, MQTT_TOPIC, MQTT_USER, MQTT_PASSWORD, MQTT_KEEPALIVE)

m = b"Testing..."

path=["ancr","ancr","ancr","ancr","ancr"]

encrypted_to_send = tor.nest_hybrid_encryption(path, m, False)
result = client.publish("ancr", encrypted_to_send)