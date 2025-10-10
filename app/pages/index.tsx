import { ConnectButton, useActiveAccount } from "thirdweb/react";
import { createThirdwebClient } from "thirdweb";
import { defineChain } from "thirdweb/chains";
import styles from "../styles/Home.module.css";
import { NextPage } from "next";
import { useState, useEffect } from "react";
import { ethers } from "ethers";
import { config } from "../lib/config";

// Create thirdweb client with production settings
const client = createThirdwebClient({
  clientId: config.thirdweb.clientId,
});

// Define Arbitrum Sepolia with public RPC
const arbitrumSepolia = defineChain({
  id: 421614,
  name: "Arbitrum Sepolia",
  nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
  rpc: "https://sepolia-rollup.arbitrum.io/rpc",
  blockExplorers: [
    {
      name: "Arbiscan",
      url: "https://sepolia.arbiscan.io",
    },
  ],
});

const Home: NextPage = () => {
  const account = useActiveAccount();
  const address = account?.address;
  const [isGeneratingProof, setIsGeneratingProof] = useState(false);
  const [proofResult, setProofResult] = useState<any>(null);
  const [error, setError] = useState("");
  const [provider, setProvider] = useState<ethers.BrowserProvider | null>(null);
  const [signer, setSigner] = useState<ethers.JsonRpcSigner | null>(null);

  // Setup ethers provider
  useEffect(() => {
    if (typeof window !== "undefined" && (window as any).ethereum) {
      const ethersProvider = new ethers.BrowserProvider(
        (window as any).ethereum
      );
      setProvider(ethersProvider);

      if (address) {
        ethersProvider.getSigner().then(setSigner);
      }
    }
  }, [address]);

  const generateProof = async () => {
    if (!address) {
      setError("Please connect wallet");
      return;
    }

    setIsGeneratingProof(true);
    setError("");
    setProofResult(null);

    try {
      const response = await fetch("/api/generate-proof", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userAddress: address,
          salt: Math.floor(Math.random() * 1000000),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Failed to generate proof");
      }

      setProofResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsGeneratingProof(false);
    }
  };

  const mintTokens = async () => {
    if (!proofResult || !address || !signer) {
      setError("Please connect wallet and generate proof first");
      return;
    }

    try {
      setError("");

      // Contract ABI for Stylus ZK Mint ERC20 contract
      const contractABI = [
        "function mintWithZkProof(address to, uint256 amount, uint8[] memory proof_data, uint256[] memory public_inputs) external returns (bool)",
        "function verifyProof(uint8[] memory proof_data, uint256[] memory public_inputs) external view returns (bool)",
        "function balanceOf(address owner) external view returns (uint256)",
        "function totalSupply() external view returns (uint256)",
        "function name() external view returns (string)",
        "function symbol() external view returns (string)",
        "function decimals() external view returns (uint8)",
        "function transfer(address from, address to, uint256 amount) external returns (bool)",
        "function approve(address owner, address spender, uint256 amount) external returns (bool)",
        "function allowance(address owner, address spender) external view returns (uint256)",
      ];

      // Create contract instance
      const contract = new ethers.Contract(
        config.contracts.zkMint,
        contractABI,
        signer
      );

      // Convert hex proof to uint8 array
      const proofHex = proofResult.proof.startsWith("0x")
        ? proofResult.proof.slice(2)
        : proofResult.proof;
      const proofBytes = Array.from(ethers.getBytes("0x" + proofHex));

      // Public signals as BigNumbers
      const publicInputs = proofResult.publicSignals.map((signal: string) =>
        BigInt(signal)
      );

      try {
        const totalSupply = await contract.totalSupply();
        const tokenName = await contract.name();
        console.log(`Token: ${tokenName}, Total Supply: ${totalSupply}`);
      } catch (contractError: any) {
        console.error("  Contract state check failed:", contractError);
        throw new Error(
          `Contract state check failed: ${contractError.message}`
        );
      }

      // First try to verify the proof to debug the issue
      try {
        const isValid = await contract.verifyProof(proofBytes, publicInputs);
      } catch (verifyError: any) {
        console.error("  Proof verification failed:", verifyError);
        console.error("  Error details:", {
          message: verifyError.message,
          code: verifyError.code,
          data: verifyError.data,
        });
        throw new Error(`Proof verification failed: ${verifyError.message}`);
      }

      // Define mint amount (1 token with 18 decimals)
      const mintAmount = ethers.parseEther("1");
      
      // Call contract function
      console.log("🚀 Calling mintWithZkProof...");
      const tx = await contract.mintWithZkProof(
        address,
        mintAmount,
        proofBytes,
        publicInputs
      );

      setError("Transaction sent! Waiting for confirmation...");
      await tx.wait();

      alert("🎉 ERC20 tokens minted successfully!");
      setProofResult(null);
      setError("");
    } catch (err: any) {
      console.error("Mint error:", err);
      setError(err.message || "Failed to mint tokens");
    }
  };

  return (
    <main className={styles.main}>
      <div className={styles.container}>
        <div className={styles.header}>
          <h1 className={styles.title}>
            <span className={styles.gradientText0}>ZK Mint</span>
          </h1>

          <p className={styles.description}>
            Mint ERC20 tokens by proving you have at least 0.01 ETH without revealing
            your exact balance
          </p>

          <div className={styles.connect}>
            <ConnectButton
              client={client}
              chain={arbitrumSepolia}
              connectModal={{ size: "compact" }}
            />
          </div>
        </div>

        {address && (
          <div className={styles.mintSection}>
            <div className={styles.card}>
              <h2>Prove ETH Balance & Mint Tokens</h2>

              <div className={styles.infoBox}>
                <p>
                  <strong>Requirements:</strong>
                </p>
                <p>
                  • Connected wallet must have at least 0.01 ETH on Arbitrum
                  Sepolia
                </p>
                <p>
                  • Proof will verify balance without revealing exact amount
                </p>
                <p>• Your current address: {address}</p>
                <p>
                  • Current network:{" "}
                  {(window as any).ethereum?.chainId
                    ? parseInt((window as any).ethereum.chainId, 16)
                    : "Unknown"}
                </p>
              </div>

              <button
                onClick={generateProof}
                disabled={isGeneratingProof || !address}
                className={styles.button}
              >
                {isGeneratingProof
                  ? "Generating Proof..."
                  : "Generate ZK Proof"}
              </button>

              {error && <div className={styles.error}>{error}</div>}

              {proofResult && (
                <div className={styles.proofResult}>
                  <h3>✅ Proof Generated!</h3>
                  <p>Asset: {proofResult.metadata.token}</p>
                  <p>Your Balance: {proofResult.metadata.userBalance} ETH</p>
                  <p>Required: {proofResult.metadata.requiredBalance} ETH</p>
                  <p>Network: {proofResult.metadata.network}</p>

                  <button onClick={mintTokens} className={styles.button}>
                    Mint ERC20 Tokens with Proof
                  </button>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </main>
  );
};

export default Home;
