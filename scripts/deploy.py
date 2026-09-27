"""Deployment script for ReleaseIntegrityOracle on GenLayer."""
import os
from dotenv import load_dotenv
from genlayer import GenLayerClient

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    rpc_url = os.getenv("GENLAYER_RPC_URL", "https://studio.genlayer.com/rpc")
    private_key = os.getenv("GENLAYER_PRIVATE_KEY")
    
    if not private_key:
        raise ValueError("CRITICAL: GENLAYER_PRIVATE_KEY is missing in .env file.")

    # Initialize the GenLayer client
    client = GenLayerClient(rpc_url=rpc_url, private_key=private_key)
    
    contract_path = os.path.join(os.path.dirname(__file__), "..", "ReleaseIntegrityOracle.py")
    
    print(f"Reading contract source from {contract_path}...")
    with open(contract_path, "r", encoding="utf-8") as f:
        contract_source = f.read()
        
    print("Initiating deployment to GenLayer network...")
    
    # Execute deployment
    tx = client.deploy_contract(
        source_code=contract_source,
        constructor_args=[]
    )
    
    print(f"Transaction broadcasted. Hash: {tx.hash}")
    client.wait_for_receipt(tx.hash)
    
    print(f"✅ Deployment successful!")
    print(f"📜 Contract Address: {tx.contract_address}")

if __name__ == "__main__":
    main()
