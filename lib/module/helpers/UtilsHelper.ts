import crypto from "crypto";
import fs from "fs";
import path from "path";
import { suid } from "rand-token";

class UtilsHelper {
  RSA_PUBLIC_KEY_FILE_NAME = "public-key";
  RSA_PRIVATE_KEY_FILE_NAME = "private-key";

  /**
   * Get scopes both in the two scopes
   * @param queryScope query scope
   * @param targetScope target scope
   */
  getMatchedScope(queryScope: string, targetScope: string) {
    const queryScopes = queryScope.split(" ");
    const targetScopes = targetScope.split(" ");
    const matches = [];
    for (const scope of queryScopes) {
      if (targetScopes.includes(scope)) {
        matches.push(scope);
      }
    }
    return matches.join(" ");
  }

  /**
   * Encrypt string with public key from a file
   * @param toEncrypt data to encrypt
   * @param publicKey RSA public key
   */
  rsaEncrypt(toEncrypt: string, publicKey: string) {
    const buffer = Buffer.from(toEncrypt);
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString("base64");
  }

  /**
   * Decrypt string with public key from a file
   * @param toDecrypt string to decrypt
   * @param privateKey RSA private key
   */
  rsaDecrypt(toDecrypt: string, privateKey: string) {
    const buffer = Buffer.from(toDecrypt, "base64");
    const decrypted = crypto.privateDecrypt(privateKey, buffer);
    return decrypted.toString("utf8");
  }

  generateAes256GcmKey() {
    return suid(32);
  }

  aes256GcmEncrypt(text: string, masterkey: string) {
    // random initialization vector
    const iv = crypto.randomBytes(16);

    // random salt
    const salt = crypto.randomBytes(64);

    // derive encryption key: 32 byte key length
    // in assumption the masterkey is a cryptographic and NOT a password there is no need for
    // a large number of iterations. It may can replaced by HKDF
    // the value of 2145 is randomly chosen!
    const key = crypto.pbkdf2Sync(masterkey, salt, 2145, 32, "sha512");

    // AES 256 GCM Mode
    const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);

    // encrypt the given text
    const encrypted = Buffer.concat([
      cipher.update(text, "utf8"),
      cipher.final(),
    ]);

    // extract the auth tag
    const tag = cipher.getAuthTag();

    // generate output
    return Buffer.concat([salt, iv, tag, encrypted]).toString("base64");
  }

  aes256GcmDecrypt(encdata: string, masterkey: string) {
    // base64 decoding
    const bData = Buffer.from(encdata, "base64");

    // convert data to buffers
    const salt = bData.slice(0, 64);
    const iv = bData.slice(64, 80);
    const tag = bData.slice(80, 96);
    const text = bData.slice(96);

    // derive key using; 32 byte key length
    const key = crypto.pbkdf2Sync(masterkey, salt, 2145, 32, "sha512");

    // AES 256 GCM Mode
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);

    // encrypt the given text
    const decrypted =
      decipher.update(text, "binary" as any, "utf8") + decipher.final("utf8");

    return decrypted;
  }

  /**
   * Get Oauth Server Provider RSA keys
   * @param keysFolderPath RSA keys folder path
   */
  getRSAKeys(
    keysFolderPath: string
  ): {
    publicKey: string | undefined;
    privateKey: string | undefined;
  } {
    // keys foleder absolute path
    const keysFolderAbsolutePath = path.resolve(keysFolderPath);
    if (!fs.existsSync(keysFolderAbsolutePath)) {
      return {
        publicKey: undefined,
        privateKey: undefined,
      };
    } else {
      const publicKeyFilePath = `${keysFolderAbsolutePath}/${this.RSA_PUBLIC_KEY_FILE_NAME}.pem`;
      const privateKeyFilePath = `${keysFolderAbsolutePath}/${this.RSA_PRIVATE_KEY_FILE_NAME}.pem`;
      return {
        publicKey: fs.existsSync(publicKeyFilePath)
          ? fs.readFileSync(publicKeyFilePath, "utf8")
          : undefined,
        privateKey: fs.existsSync(privateKeyFilePath)
          ? fs.readFileSync(privateKeyFilePath, "utf8")
          : undefined,
      };
    }
  }

  generateRsaKeys(
    keysFolderPath: string,
    overwrite: boolean = false
  ): {
    publicKey: string;
    privateKey: string;
  } {
    // keys foleder absolute path
    const keysFolderAbsolutePath = path.resolve(keysFolderPath);

    /**
     * Create keys folder if not exist
     */
    if (!fs.existsSync(keysFolderAbsolutePath)) {
      fs.mkdirSync(keysFolderAbsolutePath);
    }

    /**
     * Get existing keys
     */
    let keys = this.getRSAKeys(keysFolderPath);

    /**
     * Generate only keys do not exist or if overwrite parameter is present
     */
    if (!keys.privateKey || !keys.publicKey || overwrite) {
      /**
       * Genrate RSA keys
       */
      crypto.generateKeyPair(
        "rsa",
        {
          modulusLength: 4096,
          publicKeyEncoding: { type: "pkcs1", format: "pem" },
          privateKeyEncoding: { type: "pkcs1", format: "pem" },
        } as crypto.RSAKeyPairOptions<"pem", "pem">,
        (err: Error | null, publicKey: string, privateKey: string) => {
          if (err) {
            console.log("Failed to generate RSA keys", err);
            throw err;
          } else {
            // write public key if needed
            if (!keys.publicKey || overwrite) {
              fs.writeFileSync(
                `${keysFolderAbsolutePath}/${this.RSA_PUBLIC_KEY_FILE_NAME}.pem`,
                publicKey,
                {
                  encoding: "utf8",
                }
              );

              // set public key
              keys.publicKey = publicKey;
            }

            // write private key if needed
            if (!keys.privateKey || overwrite) {
              fs.writeFileSync(
                `${keysFolderAbsolutePath}/${this.RSA_PRIVATE_KEY_FILE_NAME}.pem`,
                privateKey,
                {
                  encoding: "utf8",
                }
              );

              // set private key
              keys.privateKey = privateKey;
            }
          }
        }
      );
    }

    return keys as any;
  }
}

export default new UtilsHelper();
