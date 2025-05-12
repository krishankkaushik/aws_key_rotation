import os
import uvicorn
from dotenv import load_dotenv

def main():
    # Load environment variables
    load_dotenv()
    
    # Ensure API key is set
    if not os.getenv('API_KEY'):
        print("Error: API_KEY environment variable not set")
        print("Please set it in your .env file or environment")
        return
    
    # Run the API
    uvicorn.run(
        "api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )

if __name__ == "__main__":
    main() 