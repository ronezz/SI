from paho.mqtt import client as mqtt_client
import tor

MQTT_SERVER = "18.101.140.151"
MQTT_USER = "sinf"
MQTT_PASSWORD = "sinf2025"
MQTT_PORT = 1883
MQTT_KEEPALIVE = 60

MY_ID = "ancr"

# While Listening...
def on_message(client, userdata, msg):
    try:
        action, who, payload = tor.decode_and_relay(msg.payload)
        if action == "forward":
            print(f"[{MY_ID}] Forwarding next hop '{who}'...")
            client.publish(who, payload)
        else:
            try:
                texto = payload.decode("utf-8")
            except:
                texto = repr(payload)
            print(f"[{MY_ID}] Message from '{who}': {texto}")
    except Exception as e:
        print(f"[{MY_ID}] Error processing message: {e}")

def main():
    c = mqtt_client.Client()
    c.username_pw_set(MQTT_USER, MQTT_PASSWORD)
    c.on_message = on_message
    c.connect(MQTT_SERVER, MQTT_PORT, MQTT_KEEPALIVE)
    c.subscribe(MY_ID)
    print(f"[{MY_ID}] Listening on topic '{MY_ID}'...")
    c.loop_forever()

if __name__ == "__main__":
    main()
