import sys

import http.server
import socketserver
import threading

class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Log the request
        print(f"Received request from {self.client_address}")
        # Send response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Request received. Exiting server.")
        # Stop the server
        print("Request received. Exiting program.")
        # Shutdown the server in a separate thread
        threading.Thread(target=self.server.shutdown).start()
        
def main():
    # Accept Command Line Arguments
    try:
        ip_address = str(sys.argv[1])
        port = int(sys.argv[2])
    except:
        print("Error accepting webserver curl arguments. Exiting trigger.")
        return -1

    handler = RequestHandler
    httpd = socketserver.TCPServer((ip_address, port), handler)
    
    try:
        print(f"Serving on port {port}")
        # Serve until shutdown is called
        httpd.serve_forever()
    except Exception as e:
        print(f"Server encountered an error: {e}")
    finally:
        # Ensure the server is properly closed and the port is freed
        httpd.server_close()
        print(f"Port {port} has been freed")
        
        return 0
    

if __name__ == "__main__":
    main()
