import asyncio
import websockets
import json

async def test():
    uri = "ws://localhost:8000/ws/b9818182-1f44-4917-b308-c5027683e9b3"
    print(f"Connecting to {uri}...")
    try:
        # Use a short timeout of 2 seconds for connection and messages
        async with websockets.connect(uri, open_timeout=2) as websocket:
            print("Connected! Fetching messages...")
            for i in range(100):
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                    print(f"--- Message {i+1} ---")
                    data = json.loads(message)
                    print(json.dumps(data, indent=2))
                except asyncio.TimeoutError:
                    print("Timeout waiting for message. No more history?")
                    break
    except Exception as e:
        print(f"Error: {e}")

asyncio.run(test())
