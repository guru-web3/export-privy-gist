@Calebh 
was able to make it work 
/**
 * Privy Wallet Manager
 * 
 * A single-file utility for Privy wallet export and decryption.
 * Handles the entire flow of creating a policy, updating a wallet,
 * exporting and decrypting the wallet.
 */
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const canonicalize = require('canonicalize');
require('dotenv').config();

// Promisify fs functions
const writeFileAsync = promisify(fs.writeFile);
const mkdirAsync = promisify(fs.mkdir);

// Configuration from environment variables
const CONFIG = {
  PRIVY_APP_ID: process.env.PRIVY_APP_ID || 'cmakvk22n01ctjo0mftzodiei',
  PRIVY_API_KEY: process.env.PRIVY_API_KEY || '2iWuDJb6PANh99xZd9JqxYUBrNy1ZXH4A39mSPyjBsr7WWfP8wKq6KpyXXaT1X3MULmQSCNsvPZZFiesXLAX7qZo',
  PRIVY_WALLET_ID: process.env.PRIVY_WALLET_ID || 'vee4aodvou2el1ytpdlxr6r8',
  PRIVY_SIGNING_KEY: process.env.PRIVY_SIGNING_KEY || 'MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsDIUdgDt25YbHlqPNOixEprBjmoVnS8t9wyi2+Gb8suhRANCAATc7OWT/HMpNyIbGOb/kkEFzt/LPMfaFFovPn6kJMOQhp2yDCbz4ftGQ+GWB8scVcO+bJmrsNDNjFF9if2ZTXLq',
  OUTPUT_DIR: process.env.OUTPUT_DIR || path.join(__dirname, 'output')
};

// Generate authorization headers for Privy API
function getAuthHeaders() {
  const authString = `${CONFIG.PRIVY_APP_ID}:${CONFIG.PRIVY_API_KEY}`;
  const base64Auth = Buffer.from(authString).toString('base64');
  return {
    'Authorization': `Basic ${base64Auth}`,
    'privy-app-id': CONFIG.PRIVY_APP_ID,
    'Content-Type': 'application/json'
  };
}

/**
 * Generates an authorization signature for Privy API requests
 */
function generateSignature({ url, body, method = "POST" }) {
  // Format the private key as PEM
  const privateKeyAsPem = `-----BEGIN PRIVATE KEY-----\n${CONFIG.PRIVY_SIGNING_KEY}\n-----END PRIVATE KEY-----`;
  
  // Create the payload object according to Privy's requirements
  const payload = {
    version: 1,
    method,
    url,
    body,
    headers: {
      "privy-app-id": CONFIG.PRIVY_APP_ID,
    },
  };

  // Canonicalize the payload to ensure consistent serialization
  const serializedPayload = canonicalize(payload);
  const serializedPayloadBuffer = Buffer.from(serializedPayload);

  try {
    const privateKey = crypto.createPrivateKey({
      key: privateKeyAsPem,
      format: "pem",
    });

    // Sign the payload
    const signatureBuffer = crypto.sign(
      "sha256",
      serializedPayloadBuffer,
      privateKey
    );
    
    return signatureBuffer.toString("base64");
  } catch (error) {
    throw new Error(`Failed to generate signature: ${error.message}`);
  }
}

/**
 * Generates a P-256 key pair for wallet export
 */
async function generateKeyPair(outputDir) {
  try {
    // Ensure output directory exists
    await mkdirAsync(outputDir, { recursive: true });
    
    // Generate a new P-256 key pair
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: {
        type: 'spki',
        format: 'der'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    // Convert the raw public key to Base64 for Privy's recipient_public_key
    const publicKeyBase64 = Buffer.from(publicKey).toString('base64');
    
    // Save the private key to a file for later decryption
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const privateKeyPath = path.join(outputDir, `privy-decrypt-key-${timestamp}.pem`);
    await writeFileAsync(privateKeyPath, privateKey);
    
    return { 
      publicKeyBase64,
      privateKeyPath
    };
  } catch (error) {
    throw new Error(`Failed to generate key pair: ${error.message}`);
  }
}

/**
 * Creates an export policy for a wallet
 */
async function createPolicy() {
  try {
    // API endpoint for creating a policy
    const url = "https://api.privy.io/v1/policies";

    // Request body for creating an export policy
    const body = {
      version: '1.0',
      name: 'Allow wallet export',
      chain_type: 'ethereum',
      rules: [
        {
          name: 'Allow private key exports',
          method: 'exportPrivateKey',
          conditions: [],
          action: 'ALLOW'
        },
        {
          name: 'Block all other actions',
          method: '*',
          conditions: [],
          action: 'DENY'
        }
      ]
    };

    // Generate the signature
    const signature = generateSignature({ url, body });

    // Make the API call
    const headers = {
      ...getAuthHeaders(),
      'privy-authorization-signature': signature
    };

    const response = await axios.post(url, body, { headers });
    return response.data;
  } catch (error) {
    throw new Error(
      `Policy creation failed: ${error.response?.data?.message || error.message}`
    );
  }
}

/**
 * Updates a wallet with a policy ID
 */
async function updateWallet(policyId) {
  try {
    // API endpoint for updating a wallet
    const url = `https://api.privy.io/v1/wallets/${CONFIG.PRIVY_WALLET_ID}`;

    // Request body
    const body = { policy_ids: [policyId] };

    // Generate the signature
    const signature = generateSignature({ url, body, method: "PATCH" });

    // Make the API call
    const headers = {
      ...getAuthHeaders(),
      'privy-authorization-signature': signature
    };

    const response = await axios.patch(url, body, { headers });
    return response.data;
  } catch (error) {
    throw new Error(
      `Wallet update failed: ${error.response?.data?.message || error.message}`
    );
  }
}

/**
 * Exports a wallet using a newly generated key pair
 */
async function exportWallet() {
  try {
    // Generate a new key pair for the export
    const { publicKeyBase64, privateKeyPath } = await generateKeyPair(CONFIG.OUTPUT_DIR);
    
    // API endpoint
    const url = `https://api.privy.io/v1/wallets/${CONFIG.PRIVY_WALLET_ID}/export`;

    // Request body with the generated public key
    const body = {
      encryption_type: "HPKE",
      recipient_public_key: publicKeyBase64,
    };

    // Generate the signature
    const signature = generateSignature({ url, body });

    // Make the API call
    const headers = {
      ...getAuthHeaders(),
      'privy-authorization-signature': signature
    };

    const response = await axios.post(url, body, { headers });

    // Save the exported encrypted data
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const encryptedDataPath = path.join(CONFIG.OUTPUT_DIR, `privy-encrypted-wallet-${timestamp}.json`);
    await writeFileAsync(encryptedDataPath, JSON.stringify(response.data, null, 2));
    
    return {
      encryptedData: response.data,
      encryptedDataPath,
      privateKeyPath
    };
  } catch (error) {
    throw new Error(
      `Export failed: ${error.response?.data?.message || error.message}`
    );
  }
}

/**
 * Decrypts the wallet private key
 */
async function decryptWallet(encryptedDataPath, privateKeyPath) {
  try {
    // Read the encrypted data and private key
    const encryptedData = JSON.parse(fs.readFileSync(encryptedDataPath, 'utf8'));
    const privateKeyPem = fs.readFileSync(privateKeyPath, 'utf8');
    
    // Check for required fields
    if (!encryptedData.ciphertext || !encryptedData.encapsulated_key) {
      throw new Error("Encrypted data missing required fields: ciphertext or encapsulated_key");
    }
    
    // Convert the private key from PEM to a crypto key object
    const privateKey = crypto.createPrivateKey(privateKeyPem);
    
    // Convert base64 encoded values to buffers
    const encapsulatedKey = Buffer.from(encryptedData.encapsulated_key, 'base64');
    const ciphertext = Buffer.from(encryptedData.ciphertext, 'base64');
    
    // Create a public key from the encapsulated key
    const publicKeyObject = crypto.createPublicKey({
      key: encapsulatedKey,
      format: 'spki',
      type: 'spki'
    });
    
    // Perform ECDH key exchange to get the shared secret
    const sharedSecret = crypto.diffieHellman({
      privateKey,
      publicKey: publicKeyObject
    });
    
    // Derive encryption key from shared secret using HKDF
    const encryptionKey = crypto.hkdfSync(
      'sha256',
      sharedSecret, 
      Buffer.from('hpke-key', 'utf8'),  // salt
      Buffer.from('privy-hpke-v1', 'utf8'),  // info
      32  // key length
    );
    
    // Extract nonce, ciphertext and authTag
    const nonce = ciphertext.slice(0, 12);
    const actualCiphertext = ciphertext.slice(12, -16);
    const authTag = ciphertext.slice(-16);
    
    // Create decipher and set auth tag
    const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey, nonce);
    decipher.setAuthTag(authTag);
    
    // Decrypt the content
    const decrypted = Buffer.concat([
      decipher.update(actualCiphertext),
      decipher.final()
    ]);
    
    // The decrypted content is the private key
    const walletPrivateKey = decrypted.toString('utf8');
    
    // Save to a file
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const outputPath = path.join(CONFIG.OUTPUT_DIR, `decrypted-wallet-key-${timestamp}.txt`);
    await writeFileAsync(outputPath, walletPrivateKey);
    
    return {
      walletPrivateKey,
      outputPath
    };
  } catch (error) {
    throw new Error(`Decryption failed: ${error.message}`);
  }
}

/**
 * Shows menu and handles user selection
 */
async function showMenu() {
  console.log('\n🔐 Privy Wallet Manager');
  console.log('====================');
  console.log('1. Export Wallet (Create Policy + Update Wallet + Export)');
  console.log('2. Decrypt Wallet');
  console.log('3. Exit');
  
  const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
  });

  return new Promise((resolve) => {
    readline.question('\nSelect an option (1-3): ', (answer) => {
      readline.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Process wallet export flow
 */
async function processExport() {
  try {
    console.log('\n📝 Creating export policy...');
    const policy = await createPolicy();
    console.log('✅ Policy created successfully:');
    console.log(`   ID: ${policy.id}`);
    
    console.log('\n🔄 Updating wallet with policy...');
    await updateWallet(policy.id);
    console.log('✅ Wallet updated successfully');
    
    console.log('\n📤 Exporting wallet...');
    const result = await exportWallet();
    
    console.log('✅ Wallet exported successfully!');
    console.log('\n📁 Files created:');
    console.log(`   Encrypted Data: ${result.encryptedDataPath}`);
    console.log(`   Private Key: ${result.privateKeyPath}`);
    
    console.log('\n⚠️  IMPORTANT: Keep the private key file secure!');
    console.log('   It will be needed to decrypt the wallet.');
    
    return { success: true, result };
  } catch (error) {
    console.error('\n❌ Error:', error.message);
    return { success: false, error };
  }
}

/**
 * Process wallet decryption
 */
async function processDecryption() {
  try {
    const readline = require('readline').createInterface({
      input: process.stdin,
      output: process.stdout
    });

    // Helper to get input
    const question = (query) => new Promise((resolve) => {
      readline.question(query, resolve);
    });

    // Get file paths from user
    console.log('\n📂 Please provide the paths to your files:');
    const encryptedDataPath = await question('Path to encrypted wallet file: ');
    const privateKeyPath = await question('Path to private key file: ');
    readline.close();
    
    // Validate files
    if (!fs.existsSync(encryptedDataPath)) {
      throw new Error(`Encrypted wallet file not found: ${encryptedDataPath}`);
    }
    
    if (!fs.existsSync(privateKeyPath)) {
      throw new Error(`Private key file not found: ${privateKeyPath}`);
    }
    
    console.log('\n🔓 Decrypting wallet...');
    const result = await decryptWallet(encryptedDataPath, privateKeyPath);
    
    console.log('✅ Wallet decrypted successfully!');
    console.log(`\n📁 Decrypted key saved to: ${result.outputPath}`);
    
    // Show the key with partial masking for security
    const displayKey = result.walletPrivateKey.substring(0, 10) + '...' + 
                      result.walletPrivateKey.substring(result.walletPrivateKey.length - 10);
    
    console.log('\n🔑 Decrypted Key (partially masked):');
    console.log(displayKey);
    
    console.log('\n⚠️  IMPORTANT: Keep this private key secure!');
    
    return { success: true, result };
  } catch (error) {
    console.error('\n❌ Error:', error.message);
    return { success: false, error };
  }
}

/**
 * Main function
 */
async function main() {
  try {
    // Ensure output directory exists
    await mkdirAsync(CONFIG.OUTPUT_DIR, { recursive: true }).catch(() => {});
    
    while (true) {
      const choice = await showMenu();
      
      switch (choice) {
        case '1':
          await processExport();
          break;
        case '2':
          await processDecryption();
          break;
        case '3':
          console.log('\n👋 Goodbye!');
          process.exit(0);
          break;
        default:
          console.log('\n❌ Invalid option. Please try again.');
      }
      
      // Simple pause before showing menu again
      await new Promise(resolve => {
        const rl = require('readline').createInterface({
          input: process.stdin,
          output: process.stdout
        });
        rl.question('\nPress Enter to continue...', () => {
          rl.close();
          resolve();
        });
      });
    }
  } catch (error) {
    console.error('\n❌ Unhandled error:', error);
    process.exit(1);
  }
}

// Execute the main function
main().catch(console.error);
