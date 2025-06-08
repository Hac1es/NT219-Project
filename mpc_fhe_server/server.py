from .app import create_app
from .config.config import PORT, DEBUG, HOST

def main():
    """Run the MPC-FHE server"""
    app = create_app()
    print(f"Starting MPC-FHE server on {HOST}:{PORT}")
    app.run(host=HOST, port=PORT, debug=DEBUG)

if __name__ == "__main__":
    main()