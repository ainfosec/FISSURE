# FISSURE Listening Post Test Scripts

These examples exercise the HIPRFISR-hosted **Listening Posts** under:

`Targets & Actions -> Listening Posts`

They are intended for development/testing and as examples of the message format a target or external process can send back to FISSURE.

## Common expected behavior

For every Listening Post type:

1. Add the post in the Dashboard with the parameters listed below.
2. Start the post.
3. Run the corresponding sender/test command.
4. The Listening Posts **Recent Activity** pane should show a `[RECV]` entry.
5. FISSURE should create a structured `listening_post` alert through the normal alert path.
6. Stop the post when finished.

A basic unassociated message is:

```json
{"alert_text":"Listening Post test"}
```

To test Target association, copy a real Target ID from the Targets tab and send:

```json
{"target_id":"<REAL_TARGET_ID>","alert_text":"Target callback received"}
```

Expected Target behavior:

- A valid exact `target_id` adds a `listening_post` entry to that Target's History.
- A missing `target_id` leaves the message unassociated.
- An unknown `target_id` still produces the alert, but FISSURE does not create or guess a Target.

Plain text also works:

```text
Listening Post plain-text test
```

JSON can use `alert_text`, `message`, or `status` for the displayed summary.

---

## 1. TCP/UDP

Add a Listening Post:

- Name: `TCP Test` or `UDP Test`
- Type: `TCP/UDP`
- Auto Start: Off
- Protocol: `TCP` or `UDP`
- Bind Address: `127.0.0.1` for local-only testing, or `0.0.0.0` to accept traffic on any Hub interface
- Port: `55555`

Run:

```bash
python3 tcp_udp_send.py --protocol tcp --host 127.0.0.1 --port 55555
```

or:

```bash
python3 tcp_udp_send.py --protocol udp --host 127.0.0.1 --port 55555
```

Target-associated test:

```bash
python3 tcp_udp_send.py --protocol tcp --host 127.0.0.1 --port 55555 --target-id '<REAL_TARGET_ID>'
```

You can also use netcat:

```bash
echo '{"alert_text":"TCP test"}' | nc 127.0.0.1 55555
echo '{"alert_text":"UDP test"}' | nc -u 127.0.0.1 55555
```

Expected endpoint text:

```text
TCP 127.0.0.1:55555
```

or:

```text
UDP 127.0.0.1:55555
```

---

## 2. ZMQ SUB

The Listening Post is the **SUB** side, so the test utility must be the **PUB** side.

Add a Listening Post:

- Name: `ZMQ Test`
- Type: `ZMQ SUB`
- Auto Start: Off
- IP Address: `localhost`
- Port: `55555`
- Topic Filter: `alerts`

Start the Listening Post first, then run:

```bash
python3 zmq_pub_test.py
```

The publisher binds to `tcp://*:55555`, waits briefly for the subscriber to connect, and publishes:

```text
alerts {"alert_text":"ZMQ Listening Post test"}
```

Target-associated test:

```bash
python3 zmq_pub_test.py --target-id '<REAL_TARGET_ID>'
```

Important: the publisher must prefix the payload with the configured topic plus a space. With Topic Filter `alerts`, the wire message is:

```text
alerts <JSON payload>
```

Expected endpoint text:

```text
tcp://localhost:55555 / alerts
```

---

## 3. Website Poller

The Listening Post periodically performs an HTTP GET. Each non-empty line returned by the website is treated as one possible message. An identical line is processed only once while that Listening Post is running.

Start the local deterministic test server:

```bash
python3 website_poller_server.py
```

Add a Listening Post:

- Name: `Website Test`
- Type: `Website Poller`
- Auto Start: Off
- URL: `http://localhost:8080`
- Check Interval (s): `2`

Start the Listening Post.

Add a new message to the website:

```bash
curl -X POST http://localhost:8080 \
  -H 'Content-Type: application/json' \
  -d '{"alert_text":"Website Poller test"}'
```

Target-associated test:

```bash
curl -X POST http://localhost:8080 \
  -H 'Content-Type: application/json' \
  -d '{"target_id":"<REAL_TARGET_ID>","alert_text":"Website target callback"}'
```

Expected:

- Within roughly the configured check interval, Recent Activity gets the new message.
- Old lines returned by the server are not repeatedly emitted during the same Listening Post run.
- Posting a new, different line produces a new event.

Expected endpoint text:

```text
http://localhost:8080
```

---

## 4. Serial Port

For a hardware-free Linux test, create two linked pseudo-terminals with `socat`.

Install if needed:

```bash
sudo apt-get install socat
```

Create the pair:

```bash
socat -d -d pty,raw,echo=0 pty,raw,echo=0
```

`socat` prints two PTY paths, for example:

```text
/dev/pts/5
/dev/pts/6
```

Leave `socat` running.

Add a Listening Post using the **first** PTY:

- Name: `Serial Test`
- Type: `Serial Port`
- Auto Start: Off
- Serial Port: `/dev/pts/5`
- Baud Rate: `9600`

If the HIPRFISR user cannot open the PTY, temporarily adjust the test-device permissions as needed, for example:

```bash
chmod 666 /dev/pts/5 /dev/pts/6
```

Start the Listening Post.

Send on the **other** PTY:

```bash
python3 serial_send_test.py --port /dev/pts/6
```

Target-associated test:

```bash
python3 serial_send_test.py --port /dev/pts/6 --target-id '<REAL_TARGET_ID>'
```

For a real serial device, point the Listening Post at the receiving device and the sender at the paired/transmitting side.

Expected endpoint text resembles:

```text
/dev/pts/5 @ 9600
```

---

## 5. Filesystem

Filesystem Listening Posts have two modes.

### New Files mode

Create a test directory:

```bash
mkdir -p /tmp/fissure-listening-post
rm -f /tmp/fissure-listening-post/*
```

Add a Listening Post:

- Name: `Filesystem New Files`
- Type: `Filesystem`
- Auto Start: Off
- Watch Mode: `New Files`
- Folder: `/tmp/fissure-listening-post`
- File Pattern: `*.txt`

Start the Listening Post.

Create a **new** matching file after the post is running:

```bash
echo '{"alert_text":"Filesystem new-file test"}' \
  > /tmp/fissure-listening-post/test1.txt
```

Target-associated test:

```bash
echo '{"target_id":"<REAL_TARGET_ID>","alert_text":"Filesystem target callback"}' \
  > /tmp/fissure-listening-post/test2.txt
```

Expected:

- Each non-empty line in a newly created matching file is emitted.
- A file that does not match the configured pattern is ignored.

### File Changes mode

Create the file before starting the post:

```bash
touch /tmp/fissure-listening-post/returns.txt
```

Add a Listening Post:

- Name: `Filesystem File Changes`
- Type: `Filesystem`
- Auto Start: Off
- Watch Mode: `File Changes`
- File Path: `/tmp/fissure-listening-post/returns.txt`

Start the Listening Post.

Append a new line:

```bash
echo '{"alert_text":"Filesystem append test"}' \
  >> /tmp/fissure-listening-post/returns.txt
```

Expected:

- Only data appended after the Listening Post starts is emitted.
- Existing content already in the file when the post starts is not replayed.

---

## 6. MQTT

For a deterministic test, a local Mosquitto broker is preferable to a public broker.

Install if needed:

```bash
sudo apt-get install mosquitto mosquitto-clients
```

Make sure the broker is running locally. For a temporary foreground broker:

```bash
mosquitto -v
```

Add a Listening Post:

- Name: `MQTT Test`
- Type: `MQTT`
- Auto Start: Off
- Broker Address: `localhost`
- Port: `1883`
- Topic: `fissure/alerts`
- Username: blank
- Password: blank

Start the Listening Post.

Publish with the included Python helper:

```bash
python3 mqtt_publish_test.py
```

or with Mosquitto:

```bash
mosquitto_pub -h localhost -p 1883 -t fissure/alerts \
  -m '{"alert_text":"MQTT Listening Post test"}'
```

Target-associated test:

```bash
python3 mqtt_publish_test.py --target-id '<REAL_TARGET_ID>'
```

Expected:

- Recent Activity first shows the MQTT connection/subscription information.
- A publication to the configured topic produces `[RECV]`.
- Publications to unrelated topics do not.

The helper also supports a remote broker if you intentionally want to test one:

```bash
python3 mqtt_publish_test.py --host test.mosquitto.org --port 1883 --topic fissure/alerts
```

A public broker is less deterministic and should not be the primary regression test.

---

## 7. Meshtastic

This test requires Meshtastic hardware. The HIPRFISR Listening Post opens one Meshtastic radio over serial and receives text packets from the mesh.

Use **two Meshtastic radios** for the cleanest test:

- Radio A: connected to HIPRFISR and owned by the Listening Post
- Radio B: used to transmit the test message

Add a Listening Post:

- Name: `Meshtastic Test`
- Type: `Meshtastic`
- Auto Start: Off
- Serial Port: the Radio A device, for example `/dev/ttyUSB0`

Start the Listening Post.

From the machine connected to Radio B, run:

```bash
python3 meshtastic_send_test.py --port /dev/ttyUSB1
```

Target-associated test:

```bash
python3 meshtastic_send_test.py --port /dev/ttyUSB1 --target-id '<REAL_TARGET_ID>'
```

The sender transmits a normal Meshtastic text message containing the JSON payload.

Expected:

- Radio A receives the text over the mesh.
- The Listening Post produces a `[RECV]` activity entry.
- FISSURE produces the normal structured Listening Post alert.
- If the JSON contains a valid exact `target_id`, the Target History is updated.

Do not try to open the same serial Meshtastic radio simultaneously from both the Listening Post and the sender script.

---

## Useful regression checks

After each transport works once:

- Stop should return the post to `Stopped`.
- Edit and Remove should be available only while stopped.
- Auto Start should persist in `YAML/listening_posts.yaml`.
- Restarting HIPRFISR should start only posts with Auto Start enabled.
- Delete should remove the persisted definition.
- A failed start should show `Error` and populate Last Error.
- Duplicate names should be rejected.

For a TCP start-error test, create two posts with the same bind address and port. Start the first, then start the second. The second should report `Error` instead of `Running`.
