from http.server import BaseHTTPRequestHandler, HTTPServer
import webbrowser
import threading
import os

# Handler personnalisé
class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            with open("index.html", "rb") as file:
                content = file.read()
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(content)
        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Fichier index.html non trouve.")

# Fonction pour lancer le serveur
def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MyHandler)
    print(f"Serveur lancé sur http://localhost:{port}")
    httpd.serve_forever()

# Point d'entrée
if __name__ == '__main__':
    port = 8000

    # Vérifie que index.html existe
    if not os.path.exists("index.html"):
        print("Erreur : fichier index.html introuvable.")
    else:
        # Lancer le serveur dans un thread
        threading.Thread(target=run_server, args=(port,), daemon=True).start()

        # Ouvre automatiquement le navigateur
        webbrowser.open(f'http://localhost:{port}')

        input("Appuie sur Entrée pour quitter...\n")
