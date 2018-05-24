(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory();
	else if(typeof define === 'function' && define.amd)
		define([], factory);
	else {
		var a = factory();
		for(var i in a) (typeof exports === 'object' ? exports : root)[i] = a[i];
	}
})(window, function() {
return /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, {
/******/ 				configurable: false,
/******/ 				enumerable: true,
/******/ 				get: getter
/******/ 			});
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "/dist";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = "./src/curl.lib.js");
/******/ })
/************************************************************************/
/******/ ({

/***/ "./node_modules/crypto-js/aes.js":
/*!***************************************!*\
  !*** ./node_modules/crypto-js/aes.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./enc-base64 */ "./node_modules/crypto-js/enc-base64.js"), __webpack_require__(/*! ./md5 */ "./node_modules/crypto-js/md5.js"), __webpack_require__(/*! ./evpkdf */ "./node_modules/crypto-js/evpkdf.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    // Lookup tables
	    var SBOX = [];
	    var INV_SBOX = [];
	    var SUB_MIX_0 = [];
	    var SUB_MIX_1 = [];
	    var SUB_MIX_2 = [];
	    var SUB_MIX_3 = [];
	    var INV_SUB_MIX_0 = [];
	    var INV_SUB_MIX_1 = [];
	    var INV_SUB_MIX_2 = [];
	    var INV_SUB_MIX_3 = [];

	    // Compute lookup tables
	    (function () {
	        // Compute double table
	        var d = [];
	        for (var i = 0; i < 256; i++) {
	            if (i < 128) {
	                d[i] = i << 1;
	            } else {
	                d[i] = (i << 1) ^ 0x11b;
	            }
	        }

	        // Walk GF(2^8)
	        var x = 0;
	        var xi = 0;
	        for (var i = 0; i < 256; i++) {
	            // Compute sbox
	            var sx = xi ^ (xi << 1) ^ (xi << 2) ^ (xi << 3) ^ (xi << 4);
	            sx = (sx >>> 8) ^ (sx & 0xff) ^ 0x63;
	            SBOX[x] = sx;
	            INV_SBOX[sx] = x;

	            // Compute multiplication
	            var x2 = d[x];
	            var x4 = d[x2];
	            var x8 = d[x4];

	            // Compute sub bytes, mix columns tables
	            var t = (d[sx] * 0x101) ^ (sx * 0x1010100);
	            SUB_MIX_0[x] = (t << 24) | (t >>> 8);
	            SUB_MIX_1[x] = (t << 16) | (t >>> 16);
	            SUB_MIX_2[x] = (t << 8)  | (t >>> 24);
	            SUB_MIX_3[x] = t;

	            // Compute inv sub bytes, inv mix columns tables
	            var t = (x8 * 0x1010101) ^ (x4 * 0x10001) ^ (x2 * 0x101) ^ (x * 0x1010100);
	            INV_SUB_MIX_0[sx] = (t << 24) | (t >>> 8);
	            INV_SUB_MIX_1[sx] = (t << 16) | (t >>> 16);
	            INV_SUB_MIX_2[sx] = (t << 8)  | (t >>> 24);
	            INV_SUB_MIX_3[sx] = t;

	            // Compute next counter
	            if (!x) {
	                x = xi = 1;
	            } else {
	                x = x2 ^ d[d[d[x8 ^ x2]]];
	                xi ^= d[d[xi]];
	            }
	        }
	    }());

	    // Precomputed Rcon lookup
	    var RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

	    /**
	     * AES block cipher algorithm.
	     */
	    var AES = C_algo.AES = BlockCipher.extend({
	        _doReset: function () {
	            // Skip reset of nRounds has been set before and key did not change
	            if (this._nRounds && this._keyPriorReset === this._key) {
	                return;
	            }

	            // Shortcuts
	            var key = this._keyPriorReset = this._key;
	            var keyWords = key.words;
	            var keySize = key.sigBytes / 4;

	            // Compute number of rounds
	            var nRounds = this._nRounds = keySize + 6;

	            // Compute number of key schedule rows
	            var ksRows = (nRounds + 1) * 4;

	            // Compute key schedule
	            var keySchedule = this._keySchedule = [];
	            for (var ksRow = 0; ksRow < ksRows; ksRow++) {
	                if (ksRow < keySize) {
	                    keySchedule[ksRow] = keyWords[ksRow];
	                } else {
	                    var t = keySchedule[ksRow - 1];

	                    if (!(ksRow % keySize)) {
	                        // Rot word
	                        t = (t << 8) | (t >>> 24);

	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];

	                        // Mix Rcon
	                        t ^= RCON[(ksRow / keySize) | 0] << 24;
	                    } else if (keySize > 6 && ksRow % keySize == 4) {
	                        // Sub word
	                        t = (SBOX[t >>> 24] << 24) | (SBOX[(t >>> 16) & 0xff] << 16) | (SBOX[(t >>> 8) & 0xff] << 8) | SBOX[t & 0xff];
	                    }

	                    keySchedule[ksRow] = keySchedule[ksRow - keySize] ^ t;
	                }
	            }

	            // Compute inv key schedule
	            var invKeySchedule = this._invKeySchedule = [];
	            for (var invKsRow = 0; invKsRow < ksRows; invKsRow++) {
	                var ksRow = ksRows - invKsRow;

	                if (invKsRow % 4) {
	                    var t = keySchedule[ksRow];
	                } else {
	                    var t = keySchedule[ksRow - 4];
	                }

	                if (invKsRow < 4 || ksRow <= 4) {
	                    invKeySchedule[invKsRow] = t;
	                } else {
	                    invKeySchedule[invKsRow] = INV_SUB_MIX_0[SBOX[t >>> 24]] ^ INV_SUB_MIX_1[SBOX[(t >>> 16) & 0xff]] ^
	                                               INV_SUB_MIX_2[SBOX[(t >>> 8) & 0xff]] ^ INV_SUB_MIX_3[SBOX[t & 0xff]];
	                }
	            }
	        },

	        encryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX);
	        },

	        decryptBlock: function (M, offset) {
	            // Swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;

	            this._doCryptBlock(M, offset, this._invKeySchedule, INV_SUB_MIX_0, INV_SUB_MIX_1, INV_SUB_MIX_2, INV_SUB_MIX_3, INV_SBOX);

	            // Inv swap 2nd and 4th rows
	            var t = M[offset + 1];
	            M[offset + 1] = M[offset + 3];
	            M[offset + 3] = t;
	        },

	        _doCryptBlock: function (M, offset, keySchedule, SUB_MIX_0, SUB_MIX_1, SUB_MIX_2, SUB_MIX_3, SBOX) {
	            // Shortcut
	            var nRounds = this._nRounds;

	            // Get input, add round key
	            var s0 = M[offset]     ^ keySchedule[0];
	            var s1 = M[offset + 1] ^ keySchedule[1];
	            var s2 = M[offset + 2] ^ keySchedule[2];
	            var s3 = M[offset + 3] ^ keySchedule[3];

	            // Key schedule row counter
	            var ksRow = 4;

	            // Rounds
	            for (var round = 1; round < nRounds; round++) {
	                // Shift rows, sub bytes, mix columns, add round key
	                var t0 = SUB_MIX_0[s0 >>> 24] ^ SUB_MIX_1[(s1 >>> 16) & 0xff] ^ SUB_MIX_2[(s2 >>> 8) & 0xff] ^ SUB_MIX_3[s3 & 0xff] ^ keySchedule[ksRow++];
	                var t1 = SUB_MIX_0[s1 >>> 24] ^ SUB_MIX_1[(s2 >>> 16) & 0xff] ^ SUB_MIX_2[(s3 >>> 8) & 0xff] ^ SUB_MIX_3[s0 & 0xff] ^ keySchedule[ksRow++];
	                var t2 = SUB_MIX_0[s2 >>> 24] ^ SUB_MIX_1[(s3 >>> 16) & 0xff] ^ SUB_MIX_2[(s0 >>> 8) & 0xff] ^ SUB_MIX_3[s1 & 0xff] ^ keySchedule[ksRow++];
	                var t3 = SUB_MIX_0[s3 >>> 24] ^ SUB_MIX_1[(s0 >>> 16) & 0xff] ^ SUB_MIX_2[(s1 >>> 8) & 0xff] ^ SUB_MIX_3[s2 & 0xff] ^ keySchedule[ksRow++];

	                // Update state
	                s0 = t0;
	                s1 = t1;
	                s2 = t2;
	                s3 = t3;
	            }

	            // Shift rows, sub bytes, add round key
	            var t0 = ((SBOX[s0 >>> 24] << 24) | (SBOX[(s1 >>> 16) & 0xff] << 16) | (SBOX[(s2 >>> 8) & 0xff] << 8) | SBOX[s3 & 0xff]) ^ keySchedule[ksRow++];
	            var t1 = ((SBOX[s1 >>> 24] << 24) | (SBOX[(s2 >>> 16) & 0xff] << 16) | (SBOX[(s3 >>> 8) & 0xff] << 8) | SBOX[s0 & 0xff]) ^ keySchedule[ksRow++];
	            var t2 = ((SBOX[s2 >>> 24] << 24) | (SBOX[(s3 >>> 16) & 0xff] << 16) | (SBOX[(s0 >>> 8) & 0xff] << 8) | SBOX[s1 & 0xff]) ^ keySchedule[ksRow++];
	            var t3 = ((SBOX[s3 >>> 24] << 24) | (SBOX[(s0 >>> 16) & 0xff] << 16) | (SBOX[(s1 >>> 8) & 0xff] << 8) | SBOX[s2 & 0xff]) ^ keySchedule[ksRow++];

	            // Set output
	            M[offset]     = t0;
	            M[offset + 1] = t1;
	            M[offset + 2] = t2;
	            M[offset + 3] = t3;
	        },

	        keySize: 256/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.AES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.AES.decrypt(ciphertext, key, cfg);
	     */
	    C.AES = BlockCipher._createHelper(AES);
	}());


	return CryptoJS.AES;

}));

/***/ }),

/***/ "./node_modules/crypto-js/cipher-core.js":
/*!***********************************************!*\
  !*** ./node_modules/crypto-js/cipher-core.js ***!
  \***********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./evpkdf */ "./node_modules/crypto-js/evpkdf.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Cipher core components.
	 */
	CryptoJS.lib.Cipher || (function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var Base64 = C_enc.Base64;
	    var C_algo = C.algo;
	    var EvpKDF = C_algo.EvpKDF;

	    /**
	     * Abstract base cipher template.
	     *
	     * @property {number} keySize This cipher's key size. Default: 4 (128 bits)
	     * @property {number} ivSize This cipher's IV size. Default: 4 (128 bits)
	     * @property {number} _ENC_XFORM_MODE A constant representing encryption mode.
	     * @property {number} _DEC_XFORM_MODE A constant representing decryption mode.
	     */
	    var Cipher = C_lib.Cipher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {WordArray} iv The IV to use for this operation.
	         */
	        cfg: Base.extend(),

	        /**
	         * Creates this cipher in encryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createEncryptor: function (key, cfg) {
	            return this.create(this._ENC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Creates this cipher in decryption mode.
	         *
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {Cipher} A cipher instance.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
	         */
	        createDecryptor: function (key, cfg) {
	            return this.create(this._DEC_XFORM_MODE, key, cfg);
	        },

	        /**
	         * Initializes a newly created cipher.
	         *
	         * @param {number} xformMode Either the encryption or decryption transormation mode constant.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @example
	         *
	         *     var cipher = CryptoJS.algo.AES.create(CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
	         */
	        init: function (xformMode, key, cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Store transform mode and key
	            this._xformMode = xformMode;
	            this._key = key;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this cipher to its initial state.
	         *
	         * @example
	         *
	         *     cipher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-cipher logic
	            this._doReset();
	        },

	        /**
	         * Adds data to be encrypted or decrypted.
	         *
	         * @param {WordArray|string} dataUpdate The data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.process('data');
	         *     var encrypted = cipher.process(wordArray);
	         */
	        process: function (dataUpdate) {
	            // Append
	            this._append(dataUpdate);

	            // Process available blocks
	            return this._process();
	        },

	        /**
	         * Finalizes the encryption or decryption process.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} dataUpdate The final data to encrypt or decrypt.
	         *
	         * @return {WordArray} The data after final processing.
	         *
	         * @example
	         *
	         *     var encrypted = cipher.finalize();
	         *     var encrypted = cipher.finalize('data');
	         *     var encrypted = cipher.finalize(wordArray);
	         */
	        finalize: function (dataUpdate) {
	            // Final data update
	            if (dataUpdate) {
	                this._append(dataUpdate);
	            }

	            // Perform concrete-cipher logic
	            var finalProcessedData = this._doFinalize();

	            return finalProcessedData;
	        },

	        keySize: 128/32,

	        ivSize: 128/32,

	        _ENC_XFORM_MODE: 1,

	        _DEC_XFORM_MODE: 2,

	        /**
	         * Creates shortcut functions to a cipher's object interface.
	         *
	         * @param {Cipher} cipher The cipher to create a helper for.
	         *
	         * @return {Object} An object with encrypt and decrypt shortcut functions.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var AES = CryptoJS.lib.Cipher._createHelper(CryptoJS.algo.AES);
	         */
	        _createHelper: (function () {
	            function selectCipherStrategy(key) {
	                if (typeof key == 'string') {
	                    return PasswordBasedCipher;
	                } else {
	                    return SerializableCipher;
	                }
	            }

	            return function (cipher) {
	                return {
	                    encrypt: function (message, key, cfg) {
	                        return selectCipherStrategy(key).encrypt(cipher, message, key, cfg);
	                    },

	                    decrypt: function (ciphertext, key, cfg) {
	                        return selectCipherStrategy(key).decrypt(cipher, ciphertext, key, cfg);
	                    }
	                };
	            };
	        }())
	    });

	    /**
	     * Abstract base stream cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 1 (32 bits)
	     */
	    var StreamCipher = C_lib.StreamCipher = Cipher.extend({
	        _doFinalize: function () {
	            // Process partial blocks
	            var finalProcessedBlocks = this._process(!!'flush');

	            return finalProcessedBlocks;
	        },

	        blockSize: 1
	    });

	    /**
	     * Mode namespace.
	     */
	    var C_mode = C.mode = {};

	    /**
	     * Abstract base block cipher mode template.
	     */
	    var BlockCipherMode = C_lib.BlockCipherMode = Base.extend({
	        /**
	         * Creates this mode for encryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createEncryptor(cipher, iv.words);
	         */
	        createEncryptor: function (cipher, iv) {
	            return this.Encryptor.create(cipher, iv);
	        },

	        /**
	         * Creates this mode for decryption.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.createDecryptor(cipher, iv.words);
	         */
	        createDecryptor: function (cipher, iv) {
	            return this.Decryptor.create(cipher, iv);
	        },

	        /**
	         * Initializes a newly created mode.
	         *
	         * @param {Cipher} cipher A block cipher instance.
	         * @param {Array} iv The IV words.
	         *
	         * @example
	         *
	         *     var mode = CryptoJS.mode.CBC.Encryptor.create(cipher, iv.words);
	         */
	        init: function (cipher, iv) {
	            this._cipher = cipher;
	            this._iv = iv;
	        }
	    });

	    /**
	     * Cipher Block Chaining mode.
	     */
	    var CBC = C_mode.CBC = (function () {
	        /**
	         * Abstract base CBC mode.
	         */
	        var CBC = BlockCipherMode.extend();

	        /**
	         * CBC encryptor.
	         */
	        CBC.Encryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // XOR and encrypt
	                xorBlock.call(this, words, offset, blockSize);
	                cipher.encryptBlock(words, offset);

	                // Remember this block to use with next block
	                this._prevBlock = words.slice(offset, offset + blockSize);
	            }
	        });

	        /**
	         * CBC decryptor.
	         */
	        CBC.Decryptor = CBC.extend({
	            /**
	             * Processes the data block at offset.
	             *
	             * @param {Array} words The data words to operate on.
	             * @param {number} offset The offset where the block starts.
	             *
	             * @example
	             *
	             *     mode.processBlock(data.words, offset);
	             */
	            processBlock: function (words, offset) {
	                // Shortcuts
	                var cipher = this._cipher;
	                var blockSize = cipher.blockSize;

	                // Remember this block to use with next block
	                var thisBlock = words.slice(offset, offset + blockSize);

	                // Decrypt and XOR
	                cipher.decryptBlock(words, offset);
	                xorBlock.call(this, words, offset, blockSize);

	                // This block becomes the previous block
	                this._prevBlock = thisBlock;
	            }
	        });

	        function xorBlock(words, offset, blockSize) {
	            // Shortcut
	            var iv = this._iv;

	            // Choose mixing block
	            if (iv) {
	                var block = iv;

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            } else {
	                var block = this._prevBlock;
	            }

	            // XOR blocks
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= block[i];
	            }
	        }

	        return CBC;
	    }());

	    /**
	     * Padding namespace.
	     */
	    var C_pad = C.pad = {};

	    /**
	     * PKCS #5/7 padding strategy.
	     */
	    var Pkcs7 = C_pad.Pkcs7 = {
	        /**
	         * Pads data using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to pad.
	         * @param {number} blockSize The multiple that the data should be padded to.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
	         */
	        pad: function (data, blockSize) {
	            // Shortcut
	            var blockSizeBytes = blockSize * 4;

	            // Count padding bytes
	            var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

	            // Create padding word
	            var paddingWord = (nPaddingBytes << 24) | (nPaddingBytes << 16) | (nPaddingBytes << 8) | nPaddingBytes;

	            // Create padding
	            var paddingWords = [];
	            for (var i = 0; i < nPaddingBytes; i += 4) {
	                paddingWords.push(paddingWord);
	            }
	            var padding = WordArray.create(paddingWords, nPaddingBytes);

	            // Add padding
	            data.concat(padding);
	        },

	        /**
	         * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
	         *
	         * @param {WordArray} data The data to unpad.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     CryptoJS.pad.Pkcs7.unpad(wordArray);
	         */
	        unpad: function (data) {
	            // Get number of padding bytes from last byte
	            var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	            // Remove padding
	            data.sigBytes -= nPaddingBytes;
	        }
	    };

	    /**
	     * Abstract base block cipher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this cipher operates on. Default: 4 (128 bits)
	     */
	    var BlockCipher = C_lib.BlockCipher = Cipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Mode} mode The block mode to use. Default: CBC
	         * @property {Padding} padding The padding strategy to use. Default: Pkcs7
	         */
	        cfg: Cipher.cfg.extend({
	            mode: CBC,
	            padding: Pkcs7
	        }),

	        reset: function () {
	            // Reset cipher
	            Cipher.reset.call(this);

	            // Shortcuts
	            var cfg = this.cfg;
	            var iv = cfg.iv;
	            var mode = cfg.mode;

	            // Reset block mode
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                var modeCreator = mode.createEncryptor;
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                var modeCreator = mode.createDecryptor;
	                // Keep at least one block in the buffer for unpadding
	                this._minBufferSize = 1;
	            }

	            if (this._mode && this._mode.__creator == modeCreator) {
	                this._mode.init(this, iv && iv.words);
	            } else {
	                this._mode = modeCreator.call(mode, this, iv && iv.words);
	                this._mode.__creator = modeCreator;
	            }
	        },

	        _doProcessBlock: function (words, offset) {
	            this._mode.processBlock(words, offset);
	        },

	        _doFinalize: function () {
	            // Shortcut
	            var padding = this.cfg.padding;

	            // Finalize
	            if (this._xformMode == this._ENC_XFORM_MODE) {
	                // Pad data
	                padding.pad(this._data, this.blockSize);

	                // Process final blocks
	                var finalProcessedBlocks = this._process(!!'flush');
	            } else /* if (this._xformMode == this._DEC_XFORM_MODE) */ {
	                // Process final blocks
	                var finalProcessedBlocks = this._process(!!'flush');

	                // Unpad data
	                padding.unpad(finalProcessedBlocks);
	            }

	            return finalProcessedBlocks;
	        },

	        blockSize: 128/32
	    });

	    /**
	     * A collection of cipher parameters.
	     *
	     * @property {WordArray} ciphertext The raw ciphertext.
	     * @property {WordArray} key The key to this ciphertext.
	     * @property {WordArray} iv The IV used in the ciphering operation.
	     * @property {WordArray} salt The salt used with a key derivation function.
	     * @property {Cipher} algorithm The cipher algorithm.
	     * @property {Mode} mode The block mode used in the ciphering operation.
	     * @property {Padding} padding The padding scheme used in the ciphering operation.
	     * @property {number} blockSize The block size of the cipher.
	     * @property {Format} formatter The default formatting strategy to convert this cipher params object to a string.
	     */
	    var CipherParams = C_lib.CipherParams = Base.extend({
	        /**
	         * Initializes a newly created cipher params object.
	         *
	         * @param {Object} cipherParams An object with any of the possible cipher parameters.
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.lib.CipherParams.create({
	         *         ciphertext: ciphertextWordArray,
	         *         key: keyWordArray,
	         *         iv: ivWordArray,
	         *         salt: saltWordArray,
	         *         algorithm: CryptoJS.algo.AES,
	         *         mode: CryptoJS.mode.CBC,
	         *         padding: CryptoJS.pad.PKCS7,
	         *         blockSize: 4,
	         *         formatter: CryptoJS.format.OpenSSL
	         *     });
	         */
	        init: function (cipherParams) {
	            this.mixIn(cipherParams);
	        },

	        /**
	         * Converts this cipher params object to a string.
	         *
	         * @param {Format} formatter (Optional) The formatting strategy to use.
	         *
	         * @return {string} The stringified cipher params.
	         *
	         * @throws Error If neither the formatter nor the default formatter is set.
	         *
	         * @example
	         *
	         *     var string = cipherParams + '';
	         *     var string = cipherParams.toString();
	         *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
	         */
	        toString: function (formatter) {
	            return (formatter || this.formatter).stringify(this);
	        }
	    });

	    /**
	     * Format namespace.
	     */
	    var C_format = C.format = {};

	    /**
	     * OpenSSL formatting strategy.
	     */
	    var OpenSSLFormatter = C_format.OpenSSL = {
	        /**
	         * Converts a cipher params object to an OpenSSL-compatible string.
	         *
	         * @param {CipherParams} cipherParams The cipher params object.
	         *
	         * @return {string} The OpenSSL-compatible string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
	         */
	        stringify: function (cipherParams) {
	            // Shortcuts
	            var ciphertext = cipherParams.ciphertext;
	            var salt = cipherParams.salt;

	            // Format
	            if (salt) {
	                var wordArray = WordArray.create([0x53616c74, 0x65645f5f]).concat(salt).concat(ciphertext);
	            } else {
	                var wordArray = ciphertext;
	            }

	            return wordArray.toString(Base64);
	        },

	        /**
	         * Converts an OpenSSL-compatible string to a cipher params object.
	         *
	         * @param {string} openSSLStr The OpenSSL-compatible string.
	         *
	         * @return {CipherParams} The cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
	         */
	        parse: function (openSSLStr) {
	            // Parse base64
	            var ciphertext = Base64.parse(openSSLStr);

	            // Shortcut
	            var ciphertextWords = ciphertext.words;

	            // Test for salt
	            if (ciphertextWords[0] == 0x53616c74 && ciphertextWords[1] == 0x65645f5f) {
	                // Extract salt
	                var salt = WordArray.create(ciphertextWords.slice(2, 4));

	                // Remove salt from ciphertext
	                ciphertextWords.splice(0, 4);
	                ciphertext.sigBytes -= 16;
	            }

	            return CipherParams.create({ ciphertext: ciphertext, salt: salt });
	        }
	    };

	    /**
	     * A cipher wrapper that returns ciphertext as a serializable cipher params object.
	     */
	    var SerializableCipher = C_lib.SerializableCipher = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {Formatter} format The formatting strategy to convert cipher param objects to and from a string. Default: OpenSSL
	         */
	        cfg: Base.extend({
	            format: OpenSSLFormatter
	        }),

	        /**
	         * Encrypts a message.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key);
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv });
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher.encrypt(CryptoJS.algo.AES, message, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Encrypt
	            var encryptor = cipher.createEncryptor(key, cfg);
	            var ciphertext = encryptor.finalize(message);

	            // Shortcut
	            var cipherCfg = encryptor.cfg;

	            // Create and return serializable cipher params
	            return CipherParams.create({
	                ciphertext: ciphertext,
	                key: key,
	                iv: cipherCfg.iv,
	                algorithm: cipher,
	                mode: cipherCfg.mode,
	                padding: cipherCfg.padding,
	                blockSize: cipher.blockSize,
	                formatter: cfg.format
	            });
	        },

	        /**
	         * Decrypts serialized ciphertext.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {WordArray} key The key.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.SerializableCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, key, { iv: iv, format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, key, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Decrypt
	            var plaintext = cipher.createDecryptor(key, cfg).finalize(ciphertext.ciphertext);

	            return plaintext;
	        },

	        /**
	         * Converts serialized ciphertext to CipherParams,
	         * else assumed CipherParams already and returns ciphertext unchanged.
	         *
	         * @param {CipherParams|string} ciphertext The ciphertext.
	         * @param {Formatter} format The formatting strategy to use to parse serialized ciphertext.
	         *
	         * @return {CipherParams} The unserialized ciphertext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.SerializableCipher._parse(ciphertextStringOrParams, format);
	         */
	        _parse: function (ciphertext, format) {
	            if (typeof ciphertext == 'string') {
	                return format.parse(ciphertext, this);
	            } else {
	                return ciphertext;
	            }
	        }
	    });

	    /**
	     * Key derivation function namespace.
	     */
	    var C_kdf = C.kdf = {};

	    /**
	     * OpenSSL key derivation function.
	     */
	    var OpenSSLKdf = C_kdf.OpenSSL = {
	        /**
	         * Derives a key and IV from a password.
	         *
	         * @param {string} password The password to derive from.
	         * @param {number} keySize The size in words of the key to generate.
	         * @param {number} ivSize The size in words of the IV to generate.
	         * @param {WordArray|string} salt (Optional) A 64-bit salt to use. If omitted, a salt will be generated randomly.
	         *
	         * @return {CipherParams} A cipher params object with the key, IV, and salt.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32);
	         *     var derivedParams = CryptoJS.kdf.OpenSSL.execute('Password', 256/32, 128/32, 'saltsalt');
	         */
	        execute: function (password, keySize, ivSize, salt) {
	            // Generate random salt
	            if (!salt) {
	                salt = WordArray.random(64/8);
	            }

	            // Derive key and IV
	            var key = EvpKDF.create({ keySize: keySize + ivSize }).compute(password, salt);

	            // Separate key and IV
	            var iv = WordArray.create(key.words.slice(keySize), ivSize * 4);
	            key.sigBytes = keySize * 4;

	            // Return params
	            return CipherParams.create({ key: key, iv: iv, salt: salt });
	        }
	    };

	    /**
	     * A serializable cipher wrapper that derives the key from a password,
	     * and returns ciphertext as a serializable cipher params object.
	     */
	    var PasswordBasedCipher = C_lib.PasswordBasedCipher = SerializableCipher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {KDF} kdf The key derivation function to use to generate a key and IV from a password. Default: OpenSSL
	         */
	        cfg: SerializableCipher.cfg.extend({
	            kdf: OpenSSLKdf
	        }),

	        /**
	         * Encrypts a message using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {WordArray|string} message The message to encrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {CipherParams} A cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password');
	         *     var ciphertextParams = CryptoJS.lib.PasswordBasedCipher.encrypt(CryptoJS.algo.AES, message, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        encrypt: function (cipher, message, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Encrypt
	            var ciphertext = SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);

	            // Mix in derived params
	            ciphertext.mixIn(derivedParams);

	            return ciphertext;
	        },

	        /**
	         * Decrypts serialized ciphertext using a password.
	         *
	         * @param {Cipher} cipher The cipher algorithm to use.
	         * @param {CipherParams|string} ciphertext The ciphertext to decrypt.
	         * @param {string} password The password.
	         * @param {Object} cfg (Optional) The configuration options to use for this operation.
	         *
	         * @return {WordArray} The plaintext.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, formattedCiphertext, 'password', { format: CryptoJS.format.OpenSSL });
	         *     var plaintext = CryptoJS.lib.PasswordBasedCipher.decrypt(CryptoJS.algo.AES, ciphertextParams, 'password', { format: CryptoJS.format.OpenSSL });
	         */
	        decrypt: function (cipher, ciphertext, password, cfg) {
	            // Apply config defaults
	            cfg = this.cfg.extend(cfg);

	            // Convert string to CipherParams
	            ciphertext = this._parse(ciphertext, cfg.format);

	            // Derive key and other params
	            var derivedParams = cfg.kdf.execute(password, cipher.keySize, cipher.ivSize, ciphertext.salt);

	            // Add IV to config
	            cfg.iv = derivedParams.iv;

	            // Decrypt
	            var plaintext = SerializableCipher.decrypt.call(this, cipher, ciphertext, derivedParams.key, cfg);

	            return plaintext;
	        }
	    });
	}());


}));

/***/ }),

/***/ "./node_modules/crypto-js/core.js":
/*!****************************************!*\
  !*** ./node_modules/crypto-js/core.js ***!
  \****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory();
	}
	else {}
}(this, function () {

	/**
	 * CryptoJS core components.
	 */
	var CryptoJS = CryptoJS || (function (Math, undefined) {
	    /*
	     * Local polyfil of Object.create
	     */
	    var create = Object.create || (function () {
	        function F() {};

	        return function (obj) {
	            var subtype;

	            F.prototype = obj;

	            subtype = new F();

	            F.prototype = null;

	            return subtype;
	        };
	    }())

	    /**
	     * CryptoJS namespace.
	     */
	    var C = {};

	    /**
	     * Library namespace.
	     */
	    var C_lib = C.lib = {};

	    /**
	     * Base object for prototypal inheritance.
	     */
	    var Base = C_lib.Base = (function () {


	        return {
	            /**
	             * Creates a new object that inherits from this object.
	             *
	             * @param {Object} overrides Properties to copy into the new object.
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         field: 'value',
	             *
	             *         method: function () {
	             *         }
	             *     });
	             */
	            extend: function (overrides) {
	                // Spawn
	                var subtype = create(this);

	                // Augment
	                if (overrides) {
	                    subtype.mixIn(overrides);
	                }

	                // Create default initializer
	                if (!subtype.hasOwnProperty('init') || this.init === subtype.init) {
	                    subtype.init = function () {
	                        subtype.$super.init.apply(this, arguments);
	                    };
	                }

	                // Initializer's prototype is the subtype object
	                subtype.init.prototype = subtype;

	                // Reference supertype
	                subtype.$super = this;

	                return subtype;
	            },

	            /**
	             * Extends this object and runs the init method.
	             * Arguments to create() will be passed to init().
	             *
	             * @return {Object} The new object.
	             *
	             * @static
	             *
	             * @example
	             *
	             *     var instance = MyType.create();
	             */
	            create: function () {
	                var instance = this.extend();
	                instance.init.apply(instance, arguments);

	                return instance;
	            },

	            /**
	             * Initializes a newly created object.
	             * Override this method to add some logic when your objects are created.
	             *
	             * @example
	             *
	             *     var MyType = CryptoJS.lib.Base.extend({
	             *         init: function () {
	             *             // ...
	             *         }
	             *     });
	             */
	            init: function () {
	            },

	            /**
	             * Copies properties into this object.
	             *
	             * @param {Object} properties The properties to mix in.
	             *
	             * @example
	             *
	             *     MyType.mixIn({
	             *         field: 'value'
	             *     });
	             */
	            mixIn: function (properties) {
	                for (var propertyName in properties) {
	                    if (properties.hasOwnProperty(propertyName)) {
	                        this[propertyName] = properties[propertyName];
	                    }
	                }

	                // IE won't copy toString using the loop above
	                if (properties.hasOwnProperty('toString')) {
	                    this.toString = properties.toString;
	                }
	            },

	            /**
	             * Creates a copy of this object.
	             *
	             * @return {Object} The clone.
	             *
	             * @example
	             *
	             *     var clone = instance.clone();
	             */
	            clone: function () {
	                return this.init.prototype.extend(this);
	            }
	        };
	    }());

	    /**
	     * An array of 32-bit words.
	     *
	     * @property {Array} words The array of 32-bit words.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */
	    var WordArray = C_lib.WordArray = Base.extend({
	        /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of 32-bit words.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.create();
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607]);
	         *     var wordArray = CryptoJS.lib.WordArray.create([0x00010203, 0x04050607], 6);
	         */
	        init: function (words, sigBytes) {
	            words = this.words = words || [];

	            if (sigBytes != undefined) {
	                this.sigBytes = sigBytes;
	            } else {
	                this.sigBytes = words.length * 4;
	            }
	        },

	        /**
	         * Converts this word array to a string.
	         *
	         * @param {Encoder} encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
	         *
	         * @return {string} The stringified word array.
	         *
	         * @example
	         *
	         *     var string = wordArray + '';
	         *     var string = wordArray.toString();
	         *     var string = wordArray.toString(CryptoJS.enc.Utf8);
	         */
	        toString: function (encoder) {
	            return (encoder || Hex).stringify(this);
	        },

	        /**
	         * Concatenates a word array to this word array.
	         *
	         * @param {WordArray} wordArray The word array to append.
	         *
	         * @return {WordArray} This word array.
	         *
	         * @example
	         *
	         *     wordArray1.concat(wordArray2);
	         */
	        concat: function (wordArray) {
	            // Shortcuts
	            var thisWords = this.words;
	            var thatWords = wordArray.words;
	            var thisSigBytes = this.sigBytes;
	            var thatSigBytes = wordArray.sigBytes;

	            // Clamp excess bits
	            this.clamp();

	            // Concat
	            if (thisSigBytes % 4) {
	                // Copy one byte at a time
	                for (var i = 0; i < thatSigBytes; i++) {
	                    var thatByte = (thatWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                    thisWords[(thisSigBytes + i) >>> 2] |= thatByte << (24 - ((thisSigBytes + i) % 4) * 8);
	                }
	            } else {
	                // Copy one word at a time
	                for (var i = 0; i < thatSigBytes; i += 4) {
	                    thisWords[(thisSigBytes + i) >>> 2] = thatWords[i >>> 2];
	                }
	            }
	            this.sigBytes += thatSigBytes;

	            // Chainable
	            return this;
	        },

	        /**
	         * Removes insignificant bits.
	         *
	         * @example
	         *
	         *     wordArray.clamp();
	         */
	        clamp: function () {
	            // Shortcuts
	            var words = this.words;
	            var sigBytes = this.sigBytes;

	            // Clamp
	            words[sigBytes >>> 2] &= 0xffffffff << (32 - (sigBytes % 4) * 8);
	            words.length = Math.ceil(sigBytes / 4);
	        },

	        /**
	         * Creates a copy of this word array.
	         *
	         * @return {WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = wordArray.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone.words = this.words.slice(0);

	            return clone;
	        },

	        /**
	         * Creates a word array filled with random bytes.
	         *
	         * @param {number} nBytes The number of random bytes to generate.
	         *
	         * @return {WordArray} The random word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.lib.WordArray.random(16);
	         */
	        random: function (nBytes) {
	            var words = [];

	            var r = (function (m_w) {
	                var m_w = m_w;
	                var m_z = 0x3ade68b1;
	                var mask = 0xffffffff;

	                return function () {
	                    m_z = (0x9069 * (m_z & 0xFFFF) + (m_z >> 0x10)) & mask;
	                    m_w = (0x4650 * (m_w & 0xFFFF) + (m_w >> 0x10)) & mask;
	                    var result = ((m_z << 0x10) + m_w) & mask;
	                    result /= 0x100000000;
	                    result += 0.5;
	                    return result * (Math.random() > .5 ? 1 : -1);
	                }
	            });

	            for (var i = 0, rcache; i < nBytes; i += 4) {
	                var _r = r((rcache || Math.random()) * 0x100000000);

	                rcache = _r() * 0x3ade67b7;
	                words.push((_r() * 0x100000000) | 0);
	            }

	            return new WordArray.init(words, nBytes);
	        }
	    });

	    /**
	     * Encoder namespace.
	     */
	    var C_enc = C.enc = {};

	    /**
	     * Hex encoding strategy.
	     */
	    var Hex = C_enc.Hex = {
	        /**
	         * Converts a word array to a hex string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The hex string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var hexChars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                hexChars.push((bite >>> 4).toString(16));
	                hexChars.push((bite & 0x0f).toString(16));
	            }

	            return hexChars.join('');
	        },

	        /**
	         * Converts a hex string to a word array.
	         *
	         * @param {string} hexStr The hex string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
	         */
	        parse: function (hexStr) {
	            // Shortcut
	            var hexStrLength = hexStr.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < hexStrLength; i += 2) {
	                words[i >>> 3] |= parseInt(hexStr.substr(i, 2), 16) << (24 - (i % 8) * 4);
	            }

	            return new WordArray.init(words, hexStrLength / 2);
	        }
	    };

	    /**
	     * Latin1 encoding strategy.
	     */
	    var Latin1 = C_enc.Latin1 = {
	        /**
	         * Converts a word array to a Latin1 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Latin1 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var latin1String = CryptoJS.enc.Latin1.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var latin1Chars = [];
	            for (var i = 0; i < sigBytes; i++) {
	                var bite = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
	                latin1Chars.push(String.fromCharCode(bite));
	            }

	            return latin1Chars.join('');
	        },

	        /**
	         * Converts a Latin1 string to a word array.
	         *
	         * @param {string} latin1Str The Latin1 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Latin1.parse(latin1String);
	         */
	        parse: function (latin1Str) {
	            // Shortcut
	            var latin1StrLength = latin1Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < latin1StrLength; i++) {
	                words[i >>> 2] |= (latin1Str.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
	            }

	            return new WordArray.init(words, latin1StrLength);
	        }
	    };

	    /**
	     * UTF-8 encoding strategy.
	     */
	    var Utf8 = C_enc.Utf8 = {
	        /**
	         * Converts a word array to a UTF-8 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-8 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf8String = CryptoJS.enc.Utf8.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            try {
	                return decodeURIComponent(escape(Latin1.stringify(wordArray)));
	            } catch (e) {
	                throw new Error('Malformed UTF-8 data');
	            }
	        },

	        /**
	         * Converts a UTF-8 string to a word array.
	         *
	         * @param {string} utf8Str The UTF-8 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf8.parse(utf8String);
	         */
	        parse: function (utf8Str) {
	            return Latin1.parse(unescape(encodeURIComponent(utf8Str)));
	        }
	    };

	    /**
	     * Abstract buffered block algorithm template.
	     *
	     * The property blockSize must be implemented in a concrete subtype.
	     *
	     * @property {number} _minBufferSize The number of blocks that should be kept unprocessed in the buffer. Default: 0
	     */
	    var BufferedBlockAlgorithm = C_lib.BufferedBlockAlgorithm = Base.extend({
	        /**
	         * Resets this block algorithm's data buffer to its initial state.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm.reset();
	         */
	        reset: function () {
	            // Initial values
	            this._data = new WordArray.init();
	            this._nDataBytes = 0;
	        },

	        /**
	         * Adds new data to this block algorithm's buffer.
	         *
	         * @param {WordArray|string} data The data to append. Strings are converted to a WordArray using UTF-8.
	         *
	         * @example
	         *
	         *     bufferedBlockAlgorithm._append('data');
	         *     bufferedBlockAlgorithm._append(wordArray);
	         */
	        _append: function (data) {
	            // Convert string to WordArray, else assume WordArray already
	            if (typeof data == 'string') {
	                data = Utf8.parse(data);
	            }

	            // Append
	            this._data.concat(data);
	            this._nDataBytes += data.sigBytes;
	        },

	        /**
	         * Processes available data blocks.
	         *
	         * This method invokes _doProcessBlock(offset), which must be implemented by a concrete subtype.
	         *
	         * @param {boolean} doFlush Whether all blocks and partial blocks should be processed.
	         *
	         * @return {WordArray} The processed data.
	         *
	         * @example
	         *
	         *     var processedData = bufferedBlockAlgorithm._process();
	         *     var processedData = bufferedBlockAlgorithm._process(!!'flush');
	         */
	        _process: function (doFlush) {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;
	            var dataSigBytes = data.sigBytes;
	            var blockSize = this.blockSize;
	            var blockSizeBytes = blockSize * 4;

	            // Count blocks ready
	            var nBlocksReady = dataSigBytes / blockSizeBytes;
	            if (doFlush) {
	                // Round up to include partial blocks
	                nBlocksReady = Math.ceil(nBlocksReady);
	            } else {
	                // Round down to include only full blocks,
	                // less the number of blocks that must remain in the buffer
	                nBlocksReady = Math.max((nBlocksReady | 0) - this._minBufferSize, 0);
	            }

	            // Count words ready
	            var nWordsReady = nBlocksReady * blockSize;

	            // Count bytes ready
	            var nBytesReady = Math.min(nWordsReady * 4, dataSigBytes);

	            // Process blocks
	            if (nWordsReady) {
	                for (var offset = 0; offset < nWordsReady; offset += blockSize) {
	                    // Perform concrete-algorithm logic
	                    this._doProcessBlock(dataWords, offset);
	                }

	                // Remove processed words
	                var processedWords = dataWords.splice(0, nWordsReady);
	                data.sigBytes -= nBytesReady;
	            }

	            // Return processed words
	            return new WordArray.init(processedWords, nBytesReady);
	        },

	        /**
	         * Creates a copy of this object.
	         *
	         * @return {Object} The clone.
	         *
	         * @example
	         *
	         *     var clone = bufferedBlockAlgorithm.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);
	            clone._data = this._data.clone();

	            return clone;
	        },

	        _minBufferSize: 0
	    });

	    /**
	     * Abstract hasher template.
	     *
	     * @property {number} blockSize The number of 32-bit words this hasher operates on. Default: 16 (512 bits)
	     */
	    var Hasher = C_lib.Hasher = BufferedBlockAlgorithm.extend({
	        /**
	         * Configuration options.
	         */
	        cfg: Base.extend(),

	        /**
	         * Initializes a newly created hasher.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for this hash computation.
	         *
	         * @example
	         *
	         *     var hasher = CryptoJS.algo.SHA256.create();
	         */
	        init: function (cfg) {
	            // Apply config defaults
	            this.cfg = this.cfg.extend(cfg);

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this hasher to its initial state.
	         *
	         * @example
	         *
	         *     hasher.reset();
	         */
	        reset: function () {
	            // Reset data buffer
	            BufferedBlockAlgorithm.reset.call(this);

	            // Perform concrete-hasher logic
	            this._doReset();
	        },

	        /**
	         * Updates this hasher with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {Hasher} This hasher.
	         *
	         * @example
	         *
	         *     hasher.update('message');
	         *     hasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            // Append
	            this._append(messageUpdate);

	            // Update the hash
	            this._process();

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the hash computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The hash.
	         *
	         * @example
	         *
	         *     var hash = hasher.finalize();
	         *     var hash = hasher.finalize('message');
	         *     var hash = hasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Final message update
	            if (messageUpdate) {
	                this._append(messageUpdate);
	            }

	            // Perform concrete-hasher logic
	            var hash = this._doFinalize();

	            return hash;
	        },

	        blockSize: 512/32,

	        /**
	         * Creates a shortcut function to a hasher's object interface.
	         *
	         * @param {Hasher} hasher The hasher to create a helper for.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var SHA256 = CryptoJS.lib.Hasher._createHelper(CryptoJS.algo.SHA256);
	         */
	        _createHelper: function (hasher) {
	            return function (message, cfg) {
	                return new hasher.init(cfg).finalize(message);
	            };
	        },

	        /**
	         * Creates a shortcut function to the HMAC's object interface.
	         *
	         * @param {Hasher} hasher The hasher to use in this HMAC helper.
	         *
	         * @return {Function} The shortcut function.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var HmacSHA256 = CryptoJS.lib.Hasher._createHmacHelper(CryptoJS.algo.SHA256);
	         */
	        _createHmacHelper: function (hasher) {
	            return function (message, key) {
	                return new C_algo.HMAC.init(hasher, key).finalize(message);
	            };
	        }
	    });

	    /**
	     * Algorithm namespace.
	     */
	    var C_algo = C.algo = {};

	    return C;
	}(Math));


	return CryptoJS;

}));

/***/ }),

/***/ "./node_modules/crypto-js/enc-base64.js":
/*!**********************************************!*\
  !*** ./node_modules/crypto-js/enc-base64.js ***!
  \**********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * Base64 encoding strategy.
	     */
	    var Base64 = C_enc.Base64 = {
	        /**
	         * Converts a word array to a Base64 string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The Base64 string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var base64String = CryptoJS.enc.Base64.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;
	            var map = this._map;

	            // Clamp excess bits
	            wordArray.clamp();

	            // Convert
	            var base64Chars = [];
	            for (var i = 0; i < sigBytes; i += 3) {
	                var byte1 = (words[i >>> 2]       >>> (24 - (i % 4) * 8))       & 0xff;
	                var byte2 = (words[(i + 1) >>> 2] >>> (24 - ((i + 1) % 4) * 8)) & 0xff;
	                var byte3 = (words[(i + 2) >>> 2] >>> (24 - ((i + 2) % 4) * 8)) & 0xff;

	                var triplet = (byte1 << 16) | (byte2 << 8) | byte3;

	                for (var j = 0; (j < 4) && (i + j * 0.75 < sigBytes); j++) {
	                    base64Chars.push(map.charAt((triplet >>> (6 * (3 - j))) & 0x3f));
	                }
	            }

	            // Add padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                while (base64Chars.length % 4) {
	                    base64Chars.push(paddingChar);
	                }
	            }

	            return base64Chars.join('');
	        },

	        /**
	         * Converts a Base64 string to a word array.
	         *
	         * @param {string} base64Str The Base64 string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Base64.parse(base64String);
	         */
	        parse: function (base64Str) {
	            // Shortcuts
	            var base64StrLength = base64Str.length;
	            var map = this._map;
	            var reverseMap = this._reverseMap;

	            if (!reverseMap) {
	                    reverseMap = this._reverseMap = [];
	                    for (var j = 0; j < map.length; j++) {
	                        reverseMap[map.charCodeAt(j)] = j;
	                    }
	            }

	            // Ignore padding
	            var paddingChar = map.charAt(64);
	            if (paddingChar) {
	                var paddingIndex = base64Str.indexOf(paddingChar);
	                if (paddingIndex !== -1) {
	                    base64StrLength = paddingIndex;
	                }
	            }

	            // Convert
	            return parseLoop(base64Str, base64StrLength, reverseMap);

	        },

	        _map: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
	    };

	    function parseLoop(base64Str, base64StrLength, reverseMap) {
	      var words = [];
	      var nBytes = 0;
	      for (var i = 0; i < base64StrLength; i++) {
	          if (i % 4) {
	              var bits1 = reverseMap[base64Str.charCodeAt(i - 1)] << ((i % 4) * 2);
	              var bits2 = reverseMap[base64Str.charCodeAt(i)] >>> (6 - (i % 4) * 2);
	              words[nBytes >>> 2] |= (bits1 | bits2) << (24 - (nBytes % 4) * 8);
	              nBytes++;
	          }
	      }
	      return WordArray.create(words, nBytes);
	    }
	}());


	return CryptoJS.enc.Base64;

}));

/***/ }),

/***/ "./node_modules/crypto-js/enc-utf16.js":
/*!*********************************************!*\
  !*** ./node_modules/crypto-js/enc-utf16.js ***!
  \*********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_enc = C.enc;

	    /**
	     * UTF-16 BE encoding strategy.
	     */
	    var Utf16BE = C_enc.Utf16 = C_enc.Utf16BE = {
	        /**
	         * Converts a word array to a UTF-16 BE string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-16 BE string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf16String = CryptoJS.enc.Utf16.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var utf16Chars = [];
	            for (var i = 0; i < sigBytes; i += 2) {
	                var codePoint = (words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff;
	                utf16Chars.push(String.fromCharCode(codePoint));
	            }

	            return utf16Chars.join('');
	        },

	        /**
	         * Converts a UTF-16 BE string to a word array.
	         *
	         * @param {string} utf16Str The UTF-16 BE string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf16.parse(utf16String);
	         */
	        parse: function (utf16Str) {
	            // Shortcut
	            var utf16StrLength = utf16Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < utf16StrLength; i++) {
	                words[i >>> 1] |= utf16Str.charCodeAt(i) << (16 - (i % 2) * 16);
	            }

	            return WordArray.create(words, utf16StrLength * 2);
	        }
	    };

	    /**
	     * UTF-16 LE encoding strategy.
	     */
	    C_enc.Utf16LE = {
	        /**
	         * Converts a word array to a UTF-16 LE string.
	         *
	         * @param {WordArray} wordArray The word array.
	         *
	         * @return {string} The UTF-16 LE string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var utf16Str = CryptoJS.enc.Utf16LE.stringify(wordArray);
	         */
	        stringify: function (wordArray) {
	            // Shortcuts
	            var words = wordArray.words;
	            var sigBytes = wordArray.sigBytes;

	            // Convert
	            var utf16Chars = [];
	            for (var i = 0; i < sigBytes; i += 2) {
	                var codePoint = swapEndian((words[i >>> 2] >>> (16 - (i % 4) * 8)) & 0xffff);
	                utf16Chars.push(String.fromCharCode(codePoint));
	            }

	            return utf16Chars.join('');
	        },

	        /**
	         * Converts a UTF-16 LE string to a word array.
	         *
	         * @param {string} utf16Str The UTF-16 LE string.
	         *
	         * @return {WordArray} The word array.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.enc.Utf16LE.parse(utf16Str);
	         */
	        parse: function (utf16Str) {
	            // Shortcut
	            var utf16StrLength = utf16Str.length;

	            // Convert
	            var words = [];
	            for (var i = 0; i < utf16StrLength; i++) {
	                words[i >>> 1] |= swapEndian(utf16Str.charCodeAt(i) << (16 - (i % 2) * 16));
	            }

	            return WordArray.create(words, utf16StrLength * 2);
	        }
	    };

	    function swapEndian(word) {
	        return ((word << 8) & 0xff00ff00) | ((word >>> 8) & 0x00ff00ff);
	    }
	}());


	return CryptoJS.enc.Utf16;

}));

/***/ }),

/***/ "./node_modules/crypto-js/evpkdf.js":
/*!******************************************!*\
  !*** ./node_modules/crypto-js/evpkdf.js ***!
  \******************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./sha1 */ "./node_modules/crypto-js/sha1.js"), __webpack_require__(/*! ./hmac */ "./node_modules/crypto-js/hmac.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var MD5 = C_algo.MD5;

	    /**
	     * This key derivation function is meant to conform with EVP_BytesToKey.
	     * www.openssl.org/docs/crypto/EVP_BytesToKey.html
	     */
	    var EvpKDF = C_algo.EvpKDF = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
	         * @property {Hasher} hasher The hash algorithm to use. Default: MD5
	         * @property {number} iterations The number of iterations to perform. Default: 1
	         */
	        cfg: Base.extend({
	            keySize: 128/32,
	            hasher: MD5,
	            iterations: 1
	        }),

	        /**
	         * Initializes a newly created key derivation function.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
	         *
	         * @example
	         *
	         *     var kdf = CryptoJS.algo.EvpKDF.create();
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8 });
	         *     var kdf = CryptoJS.algo.EvpKDF.create({ keySize: 8, iterations: 1000 });
	         */
	        init: function (cfg) {
	            this.cfg = this.cfg.extend(cfg);
	        },

	        /**
	         * Derives a key from a password.
	         *
	         * @param {WordArray|string} password The password.
	         * @param {WordArray|string} salt A salt.
	         *
	         * @return {WordArray} The derived key.
	         *
	         * @example
	         *
	         *     var key = kdf.compute(password, salt);
	         */
	        compute: function (password, salt) {
	            // Shortcut
	            var cfg = this.cfg;

	            // Init hasher
	            var hasher = cfg.hasher.create();

	            // Initial values
	            var derivedKey = WordArray.create();

	            // Shortcuts
	            var derivedKeyWords = derivedKey.words;
	            var keySize = cfg.keySize;
	            var iterations = cfg.iterations;

	            // Generate key
	            while (derivedKeyWords.length < keySize) {
	                if (block) {
	                    hasher.update(block);
	                }
	                var block = hasher.update(password).finalize(salt);
	                hasher.reset();

	                // Iterations
	                for (var i = 1; i < iterations; i++) {
	                    block = hasher.finalize(block);
	                    hasher.reset();
	                }

	                derivedKey.concat(block);
	            }
	            derivedKey.sigBytes = keySize * 4;

	            return derivedKey;
	        }
	    });

	    /**
	     * Derives a key from a password.
	     *
	     * @param {WordArray|string} password The password.
	     * @param {WordArray|string} salt A salt.
	     * @param {Object} cfg (Optional) The configuration options to use for this computation.
	     *
	     * @return {WordArray} The derived key.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var key = CryptoJS.EvpKDF(password, salt);
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8 });
	     *     var key = CryptoJS.EvpKDF(password, salt, { keySize: 8, iterations: 1000 });
	     */
	    C.EvpKDF = function (password, salt, cfg) {
	        return EvpKDF.create(cfg).compute(password, salt);
	    };
	}());


	return CryptoJS.EvpKDF;

}));

/***/ }),

/***/ "./node_modules/crypto-js/format-hex.js":
/*!**********************************************!*\
  !*** ./node_modules/crypto-js/format-hex.js ***!
  \**********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var CipherParams = C_lib.CipherParams;
	    var C_enc = C.enc;
	    var Hex = C_enc.Hex;
	    var C_format = C.format;

	    var HexFormatter = C_format.Hex = {
	        /**
	         * Converts the ciphertext of a cipher params object to a hexadecimally encoded string.
	         *
	         * @param {CipherParams} cipherParams The cipher params object.
	         *
	         * @return {string} The hexadecimally encoded string.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var hexString = CryptoJS.format.Hex.stringify(cipherParams);
	         */
	        stringify: function (cipherParams) {
	            return cipherParams.ciphertext.toString(Hex);
	        },

	        /**
	         * Converts a hexadecimally encoded ciphertext string to a cipher params object.
	         *
	         * @param {string} input The hexadecimally encoded string.
	         *
	         * @return {CipherParams} The cipher params object.
	         *
	         * @static
	         *
	         * @example
	         *
	         *     var cipherParams = CryptoJS.format.Hex.parse(hexString);
	         */
	        parse: function (input) {
	            var ciphertext = Hex.parse(input);
	            return CipherParams.create({ ciphertext: ciphertext });
	        }
	    };
	}());


	return CryptoJS.format.Hex;

}));

/***/ }),

/***/ "./node_modules/crypto-js/hmac.js":
/*!****************************************!*\
  !*** ./node_modules/crypto-js/hmac.js ***!
  \****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var C_enc = C.enc;
	    var Utf8 = C_enc.Utf8;
	    var C_algo = C.algo;

	    /**
	     * HMAC algorithm.
	     */
	    var HMAC = C_algo.HMAC = Base.extend({
	        /**
	         * Initializes a newly created HMAC.
	         *
	         * @param {Hasher} hasher The hash algorithm to use.
	         * @param {WordArray|string} key The secret key.
	         *
	         * @example
	         *
	         *     var hmacHasher = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA256, key);
	         */
	        init: function (hasher, key) {
	            // Init hasher
	            hasher = this._hasher = new hasher.init();

	            // Convert string to WordArray, else assume WordArray already
	            if (typeof key == 'string') {
	                key = Utf8.parse(key);
	            }

	            // Shortcuts
	            var hasherBlockSize = hasher.blockSize;
	            var hasherBlockSizeBytes = hasherBlockSize * 4;

	            // Allow arbitrary length keys
	            if (key.sigBytes > hasherBlockSizeBytes) {
	                key = hasher.finalize(key);
	            }

	            // Clamp excess bits
	            key.clamp();

	            // Clone key for inner and outer pads
	            var oKey = this._oKey = key.clone();
	            var iKey = this._iKey = key.clone();

	            // Shortcuts
	            var oKeyWords = oKey.words;
	            var iKeyWords = iKey.words;

	            // XOR keys with pad constants
	            for (var i = 0; i < hasherBlockSize; i++) {
	                oKeyWords[i] ^= 0x5c5c5c5c;
	                iKeyWords[i] ^= 0x36363636;
	            }
	            oKey.sigBytes = iKey.sigBytes = hasherBlockSizeBytes;

	            // Set initial values
	            this.reset();
	        },

	        /**
	         * Resets this HMAC to its initial state.
	         *
	         * @example
	         *
	         *     hmacHasher.reset();
	         */
	        reset: function () {
	            // Shortcut
	            var hasher = this._hasher;

	            // Reset
	            hasher.reset();
	            hasher.update(this._iKey);
	        },

	        /**
	         * Updates this HMAC with a message.
	         *
	         * @param {WordArray|string} messageUpdate The message to append.
	         *
	         * @return {HMAC} This HMAC instance.
	         *
	         * @example
	         *
	         *     hmacHasher.update('message');
	         *     hmacHasher.update(wordArray);
	         */
	        update: function (messageUpdate) {
	            this._hasher.update(messageUpdate);

	            // Chainable
	            return this;
	        },

	        /**
	         * Finalizes the HMAC computation.
	         * Note that the finalize operation is effectively a destructive, read-once operation.
	         *
	         * @param {WordArray|string} messageUpdate (Optional) A final message update.
	         *
	         * @return {WordArray} The HMAC.
	         *
	         * @example
	         *
	         *     var hmac = hmacHasher.finalize();
	         *     var hmac = hmacHasher.finalize('message');
	         *     var hmac = hmacHasher.finalize(wordArray);
	         */
	        finalize: function (messageUpdate) {
	            // Shortcut
	            var hasher = this._hasher;

	            // Compute HMAC
	            var innerHash = hasher.finalize(messageUpdate);
	            hasher.reset();
	            var hmac = hasher.finalize(this._oKey.clone().concat(innerHash));

	            return hmac;
	        }
	    });
	}());


}));

/***/ }),

/***/ "./node_modules/crypto-js/index.js":
/*!*****************************************!*\
  !*** ./node_modules/crypto-js/index.js ***!
  \*****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./x64-core */ "./node_modules/crypto-js/x64-core.js"), __webpack_require__(/*! ./lib-typedarrays */ "./node_modules/crypto-js/lib-typedarrays.js"), __webpack_require__(/*! ./enc-utf16 */ "./node_modules/crypto-js/enc-utf16.js"), __webpack_require__(/*! ./enc-base64 */ "./node_modules/crypto-js/enc-base64.js"), __webpack_require__(/*! ./md5 */ "./node_modules/crypto-js/md5.js"), __webpack_require__(/*! ./sha1 */ "./node_modules/crypto-js/sha1.js"), __webpack_require__(/*! ./sha256 */ "./node_modules/crypto-js/sha256.js"), __webpack_require__(/*! ./sha224 */ "./node_modules/crypto-js/sha224.js"), __webpack_require__(/*! ./sha512 */ "./node_modules/crypto-js/sha512.js"), __webpack_require__(/*! ./sha384 */ "./node_modules/crypto-js/sha384.js"), __webpack_require__(/*! ./sha3 */ "./node_modules/crypto-js/sha3.js"), __webpack_require__(/*! ./ripemd160 */ "./node_modules/crypto-js/ripemd160.js"), __webpack_require__(/*! ./hmac */ "./node_modules/crypto-js/hmac.js"), __webpack_require__(/*! ./pbkdf2 */ "./node_modules/crypto-js/pbkdf2.js"), __webpack_require__(/*! ./evpkdf */ "./node_modules/crypto-js/evpkdf.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"), __webpack_require__(/*! ./mode-cfb */ "./node_modules/crypto-js/mode-cfb.js"), __webpack_require__(/*! ./mode-ctr */ "./node_modules/crypto-js/mode-ctr.js"), __webpack_require__(/*! ./mode-ctr-gladman */ "./node_modules/crypto-js/mode-ctr-gladman.js"), __webpack_require__(/*! ./mode-ofb */ "./node_modules/crypto-js/mode-ofb.js"), __webpack_require__(/*! ./mode-ecb */ "./node_modules/crypto-js/mode-ecb.js"), __webpack_require__(/*! ./pad-ansix923 */ "./node_modules/crypto-js/pad-ansix923.js"), __webpack_require__(/*! ./pad-iso10126 */ "./node_modules/crypto-js/pad-iso10126.js"), __webpack_require__(/*! ./pad-iso97971 */ "./node_modules/crypto-js/pad-iso97971.js"), __webpack_require__(/*! ./pad-zeropadding */ "./node_modules/crypto-js/pad-zeropadding.js"), __webpack_require__(/*! ./pad-nopadding */ "./node_modules/crypto-js/pad-nopadding.js"), __webpack_require__(/*! ./format-hex */ "./node_modules/crypto-js/format-hex.js"), __webpack_require__(/*! ./aes */ "./node_modules/crypto-js/aes.js"), __webpack_require__(/*! ./tripledes */ "./node_modules/crypto-js/tripledes.js"), __webpack_require__(/*! ./rc4 */ "./node_modules/crypto-js/rc4.js"), __webpack_require__(/*! ./rabbit */ "./node_modules/crypto-js/rabbit.js"), __webpack_require__(/*! ./rabbit-legacy */ "./node_modules/crypto-js/rabbit-legacy.js"));
	}
	else {}
}(this, function (CryptoJS) {

	return CryptoJS;

}));

/***/ }),

/***/ "./node_modules/crypto-js/lib-typedarrays.js":
/*!***************************************************!*\
  !*** ./node_modules/crypto-js/lib-typedarrays.js ***!
  \***************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Check if typed arrays are supported
	    if (typeof ArrayBuffer != 'function') {
	        return;
	    }

	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;

	    // Reference original init
	    var superInit = WordArray.init;

	    // Augment WordArray.init to handle typed arrays
	    var subInit = WordArray.init = function (typedArray) {
	        // Convert buffers to uint8
	        if (typedArray instanceof ArrayBuffer) {
	            typedArray = new Uint8Array(typedArray);
	        }

	        // Convert other array views to uint8
	        if (
	            typedArray instanceof Int8Array ||
	            (typeof Uint8ClampedArray !== "undefined" && typedArray instanceof Uint8ClampedArray) ||
	            typedArray instanceof Int16Array ||
	            typedArray instanceof Uint16Array ||
	            typedArray instanceof Int32Array ||
	            typedArray instanceof Uint32Array ||
	            typedArray instanceof Float32Array ||
	            typedArray instanceof Float64Array
	        ) {
	            typedArray = new Uint8Array(typedArray.buffer, typedArray.byteOffset, typedArray.byteLength);
	        }

	        // Handle Uint8Array
	        if (typedArray instanceof Uint8Array) {
	            // Shortcut
	            var typedArrayByteLength = typedArray.byteLength;

	            // Extract bytes
	            var words = [];
	            for (var i = 0; i < typedArrayByteLength; i++) {
	                words[i >>> 2] |= typedArray[i] << (24 - (i % 4) * 8);
	            }

	            // Initialize this word array
	            superInit.call(this, words, typedArrayByteLength);
	        } else {
	            // Else call normal init
	            superInit.apply(this, arguments);
	        }
	    };

	    subInit.prototype = WordArray;
	}());


	return CryptoJS.lib.WordArray;

}));

/***/ }),

/***/ "./node_modules/crypto-js/md5.js":
/*!***************************************!*\
  !*** ./node_modules/crypto-js/md5.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Constants table
	    var T = [];

	    // Compute constants
	    (function () {
	        for (var i = 0; i < 64; i++) {
	            T[i] = (Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
	        }
	    }());

	    /**
	     * MD5 hash algorithm.
	     */
	    var MD5 = C_algo.MD5 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Swap endian
	            for (var i = 0; i < 16; i++) {
	                // Shortcuts
	                var offset_i = offset + i;
	                var M_offset_i = M[offset_i];

	                M[offset_i] = (
	                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	                );
	            }

	            // Shortcuts
	            var H = this._hash.words;

	            var M_offset_0  = M[offset + 0];
	            var M_offset_1  = M[offset + 1];
	            var M_offset_2  = M[offset + 2];
	            var M_offset_3  = M[offset + 3];
	            var M_offset_4  = M[offset + 4];
	            var M_offset_5  = M[offset + 5];
	            var M_offset_6  = M[offset + 6];
	            var M_offset_7  = M[offset + 7];
	            var M_offset_8  = M[offset + 8];
	            var M_offset_9  = M[offset + 9];
	            var M_offset_10 = M[offset + 10];
	            var M_offset_11 = M[offset + 11];
	            var M_offset_12 = M[offset + 12];
	            var M_offset_13 = M[offset + 13];
	            var M_offset_14 = M[offset + 14];
	            var M_offset_15 = M[offset + 15];

	            // Working varialbes
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];

	            // Computation
	            a = FF(a, b, c, d, M_offset_0,  7,  T[0]);
	            d = FF(d, a, b, c, M_offset_1,  12, T[1]);
	            c = FF(c, d, a, b, M_offset_2,  17, T[2]);
	            b = FF(b, c, d, a, M_offset_3,  22, T[3]);
	            a = FF(a, b, c, d, M_offset_4,  7,  T[4]);
	            d = FF(d, a, b, c, M_offset_5,  12, T[5]);
	            c = FF(c, d, a, b, M_offset_6,  17, T[6]);
	            b = FF(b, c, d, a, M_offset_7,  22, T[7]);
	            a = FF(a, b, c, d, M_offset_8,  7,  T[8]);
	            d = FF(d, a, b, c, M_offset_9,  12, T[9]);
	            c = FF(c, d, a, b, M_offset_10, 17, T[10]);
	            b = FF(b, c, d, a, M_offset_11, 22, T[11]);
	            a = FF(a, b, c, d, M_offset_12, 7,  T[12]);
	            d = FF(d, a, b, c, M_offset_13, 12, T[13]);
	            c = FF(c, d, a, b, M_offset_14, 17, T[14]);
	            b = FF(b, c, d, a, M_offset_15, 22, T[15]);

	            a = GG(a, b, c, d, M_offset_1,  5,  T[16]);
	            d = GG(d, a, b, c, M_offset_6,  9,  T[17]);
	            c = GG(c, d, a, b, M_offset_11, 14, T[18]);
	            b = GG(b, c, d, a, M_offset_0,  20, T[19]);
	            a = GG(a, b, c, d, M_offset_5,  5,  T[20]);
	            d = GG(d, a, b, c, M_offset_10, 9,  T[21]);
	            c = GG(c, d, a, b, M_offset_15, 14, T[22]);
	            b = GG(b, c, d, a, M_offset_4,  20, T[23]);
	            a = GG(a, b, c, d, M_offset_9,  5,  T[24]);
	            d = GG(d, a, b, c, M_offset_14, 9,  T[25]);
	            c = GG(c, d, a, b, M_offset_3,  14, T[26]);
	            b = GG(b, c, d, a, M_offset_8,  20, T[27]);
	            a = GG(a, b, c, d, M_offset_13, 5,  T[28]);
	            d = GG(d, a, b, c, M_offset_2,  9,  T[29]);
	            c = GG(c, d, a, b, M_offset_7,  14, T[30]);
	            b = GG(b, c, d, a, M_offset_12, 20, T[31]);

	            a = HH(a, b, c, d, M_offset_5,  4,  T[32]);
	            d = HH(d, a, b, c, M_offset_8,  11, T[33]);
	            c = HH(c, d, a, b, M_offset_11, 16, T[34]);
	            b = HH(b, c, d, a, M_offset_14, 23, T[35]);
	            a = HH(a, b, c, d, M_offset_1,  4,  T[36]);
	            d = HH(d, a, b, c, M_offset_4,  11, T[37]);
	            c = HH(c, d, a, b, M_offset_7,  16, T[38]);
	            b = HH(b, c, d, a, M_offset_10, 23, T[39]);
	            a = HH(a, b, c, d, M_offset_13, 4,  T[40]);
	            d = HH(d, a, b, c, M_offset_0,  11, T[41]);
	            c = HH(c, d, a, b, M_offset_3,  16, T[42]);
	            b = HH(b, c, d, a, M_offset_6,  23, T[43]);
	            a = HH(a, b, c, d, M_offset_9,  4,  T[44]);
	            d = HH(d, a, b, c, M_offset_12, 11, T[45]);
	            c = HH(c, d, a, b, M_offset_15, 16, T[46]);
	            b = HH(b, c, d, a, M_offset_2,  23, T[47]);

	            a = II(a, b, c, d, M_offset_0,  6,  T[48]);
	            d = II(d, a, b, c, M_offset_7,  10, T[49]);
	            c = II(c, d, a, b, M_offset_14, 15, T[50]);
	            b = II(b, c, d, a, M_offset_5,  21, T[51]);
	            a = II(a, b, c, d, M_offset_12, 6,  T[52]);
	            d = II(d, a, b, c, M_offset_3,  10, T[53]);
	            c = II(c, d, a, b, M_offset_10, 15, T[54]);
	            b = II(b, c, d, a, M_offset_1,  21, T[55]);
	            a = II(a, b, c, d, M_offset_8,  6,  T[56]);
	            d = II(d, a, b, c, M_offset_15, 10, T[57]);
	            c = II(c, d, a, b, M_offset_6,  15, T[58]);
	            b = II(b, c, d, a, M_offset_13, 21, T[59]);
	            a = II(a, b, c, d, M_offset_4,  6,  T[60]);
	            d = II(d, a, b, c, M_offset_11, 10, T[61]);
	            c = II(c, d, a, b, M_offset_2,  15, T[62]);
	            b = II(b, c, d, a, M_offset_9,  21, T[63]);

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);

	            var nBitsTotalH = Math.floor(nBitsTotal / 0x100000000);
	            var nBitsTotalL = nBitsTotal;
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = (
	                (((nBitsTotalH << 8)  | (nBitsTotalH >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalH << 24) | (nBitsTotalH >>> 8))  & 0xff00ff00)
	            );
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	                (((nBitsTotalL << 8)  | (nBitsTotalL >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotalL << 24) | (nBitsTotalL >>> 8))  & 0xff00ff00)
	            );

	            data.sigBytes = (dataWords.length + 1) * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var hash = this._hash;
	            var H = hash.words;

	            // Swap endian
	            for (var i = 0; i < 4; i++) {
	                // Shortcut
	                var H_i = H[i];

	                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	            }

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    function FF(a, b, c, d, x, s, t) {
	        var n = a + ((b & c) | (~b & d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function GG(a, b, c, d, x, s, t) {
	        var n = a + ((b & d) | (c & ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function HH(a, b, c, d, x, s, t) {
	        var n = a + (b ^ c ^ d) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    function II(a, b, c, d, x, s, t) {
	        var n = a + (c ^ (b | ~d)) + x + t;
	        return ((n << s) | (n >>> (32 - s))) + b;
	    }

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.MD5('message');
	     *     var hash = CryptoJS.MD5(wordArray);
	     */
	    C.MD5 = Hasher._createHelper(MD5);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacMD5(message, key);
	     */
	    C.HmacMD5 = Hasher._createHmacHelper(MD5);
	}(Math));


	return CryptoJS.MD5;

}));

/***/ }),

/***/ "./node_modules/crypto-js/mode-cfb.js":
/*!********************************************!*\
  !*** ./node_modules/crypto-js/mode-cfb.js ***!
  \********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Cipher Feedback block mode.
	 */
	CryptoJS.mode.CFB = (function () {
	    var CFB = CryptoJS.lib.BlockCipherMode.extend();

	    CFB.Encryptor = CFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher;
	            var blockSize = cipher.blockSize;

	            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

	            // Remember this block to use with next block
	            this._prevBlock = words.slice(offset, offset + blockSize);
	        }
	    });

	    CFB.Decryptor = CFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher;
	            var blockSize = cipher.blockSize;

	            // Remember this block to use with next block
	            var thisBlock = words.slice(offset, offset + blockSize);

	            generateKeystreamAndEncrypt.call(this, words, offset, blockSize, cipher);

	            // This block becomes the previous block
	            this._prevBlock = thisBlock;
	        }
	    });

	    function generateKeystreamAndEncrypt(words, offset, blockSize, cipher) {
	        // Shortcut
	        var iv = this._iv;

	        // Generate keystream
	        if (iv) {
	            var keystream = iv.slice(0);

	            // Remove IV for subsequent blocks
	            this._iv = undefined;
	        } else {
	            var keystream = this._prevBlock;
	        }
	        cipher.encryptBlock(keystream, 0);

	        // Encrypt
	        for (var i = 0; i < blockSize; i++) {
	            words[offset + i] ^= keystream[i];
	        }
	    }

	    return CFB;
	}());


	return CryptoJS.mode.CFB;

}));

/***/ }),

/***/ "./node_modules/crypto-js/mode-ctr-gladman.js":
/*!****************************************************!*\
  !*** ./node_modules/crypto-js/mode-ctr-gladman.js ***!
  \****************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/** @preserve
	 * Counter block mode compatible with  Dr Brian Gladman fileenc.c
	 * derived from CryptoJS.mode.CTR
	 * Jan Hruby jhruby.web@gmail.com
	 */
	CryptoJS.mode.CTRGladman = (function () {
	    var CTRGladman = CryptoJS.lib.BlockCipherMode.extend();

		function incWord(word)
		{
			if (((word >> 24) & 0xff) === 0xff) { //overflow
			var b1 = (word >> 16)&0xff;
			var b2 = (word >> 8)&0xff;
			var b3 = word & 0xff;

			if (b1 === 0xff) // overflow b1
			{
			b1 = 0;
			if (b2 === 0xff)
			{
				b2 = 0;
				if (b3 === 0xff)
				{
					b3 = 0;
				}
				else
				{
					++b3;
				}
			}
			else
			{
				++b2;
			}
			}
			else
			{
			++b1;
			}

			word = 0;
			word += (b1 << 16);
			word += (b2 << 8);
			word += b3;
			}
			else
			{
			word += (0x01 << 24);
			}
			return word;
		}

		function incCounter(counter)
		{
			if ((counter[0] = incWord(counter[0])) === 0)
			{
				// encr_data in fileenc.c from  Dr Brian Gladman's counts only with DWORD j < 8
				counter[1] = incWord(counter[1]);
			}
			return counter;
		}

	    var Encryptor = CTRGladman.Encryptor = CTRGladman.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var counter = this._counter;

	            // Generate keystream
	            if (iv) {
	                counter = this._counter = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }

				incCounter(counter);

				var keystream = counter.slice(0);
	            cipher.encryptBlock(keystream, 0);

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    CTRGladman.Decryptor = Encryptor;

	    return CTRGladman;
	}());




	return CryptoJS.mode.CTRGladman;

}));

/***/ }),

/***/ "./node_modules/crypto-js/mode-ctr.js":
/*!********************************************!*\
  !*** ./node_modules/crypto-js/mode-ctr.js ***!
  \********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Counter block mode.
	 */
	CryptoJS.mode.CTR = (function () {
	    var CTR = CryptoJS.lib.BlockCipherMode.extend();

	    var Encryptor = CTR.Encryptor = CTR.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var counter = this._counter;

	            // Generate keystream
	            if (iv) {
	                counter = this._counter = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }
	            var keystream = counter.slice(0);
	            cipher.encryptBlock(keystream, 0);

	            // Increment counter
	            counter[blockSize - 1] = (counter[blockSize - 1] + 1) | 0

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    CTR.Decryptor = Encryptor;

	    return CTR;
	}());


	return CryptoJS.mode.CTR;

}));

/***/ }),

/***/ "./node_modules/crypto-js/mode-ecb.js":
/*!********************************************!*\
  !*** ./node_modules/crypto-js/mode-ecb.js ***!
  \********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Electronic Codebook block mode.
	 */
	CryptoJS.mode.ECB = (function () {
	    var ECB = CryptoJS.lib.BlockCipherMode.extend();

	    ECB.Encryptor = ECB.extend({
	        processBlock: function (words, offset) {
	            this._cipher.encryptBlock(words, offset);
	        }
	    });

	    ECB.Decryptor = ECB.extend({
	        processBlock: function (words, offset) {
	            this._cipher.decryptBlock(words, offset);
	        }
	    });

	    return ECB;
	}());


	return CryptoJS.mode.ECB;

}));

/***/ }),

/***/ "./node_modules/crypto-js/mode-ofb.js":
/*!********************************************!*\
  !*** ./node_modules/crypto-js/mode-ofb.js ***!
  \********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Output Feedback block mode.
	 */
	CryptoJS.mode.OFB = (function () {
	    var OFB = CryptoJS.lib.BlockCipherMode.extend();

	    var Encryptor = OFB.Encryptor = OFB.extend({
	        processBlock: function (words, offset) {
	            // Shortcuts
	            var cipher = this._cipher
	            var blockSize = cipher.blockSize;
	            var iv = this._iv;
	            var keystream = this._keystream;

	            // Generate keystream
	            if (iv) {
	                keystream = this._keystream = iv.slice(0);

	                // Remove IV for subsequent blocks
	                this._iv = undefined;
	            }
	            cipher.encryptBlock(keystream, 0);

	            // Encrypt
	            for (var i = 0; i < blockSize; i++) {
	                words[offset + i] ^= keystream[i];
	            }
	        }
	    });

	    OFB.Decryptor = Encryptor;

	    return OFB;
	}());


	return CryptoJS.mode.OFB;

}));

/***/ }),

/***/ "./node_modules/crypto-js/pad-ansix923.js":
/*!************************************************!*\
  !*** ./node_modules/crypto-js/pad-ansix923.js ***!
  \************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * ANSI X.923 padding strategy.
	 */
	CryptoJS.pad.AnsiX923 = {
	    pad: function (data, blockSize) {
	        // Shortcuts
	        var dataSigBytes = data.sigBytes;
	        var blockSizeBytes = blockSize * 4;

	        // Count padding bytes
	        var nPaddingBytes = blockSizeBytes - dataSigBytes % blockSizeBytes;

	        // Compute last byte position
	        var lastBytePos = dataSigBytes + nPaddingBytes - 1;

	        // Pad
	        data.clamp();
	        data.words[lastBytePos >>> 2] |= nPaddingBytes << (24 - (lastBytePos % 4) * 8);
	        data.sigBytes += nPaddingBytes;
	    },

	    unpad: function (data) {
	        // Get number of padding bytes from last byte
	        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	        // Remove padding
	        data.sigBytes -= nPaddingBytes;
	    }
	};


	return CryptoJS.pad.Ansix923;

}));

/***/ }),

/***/ "./node_modules/crypto-js/pad-iso10126.js":
/*!************************************************!*\
  !*** ./node_modules/crypto-js/pad-iso10126.js ***!
  \************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * ISO 10126 padding strategy.
	 */
	CryptoJS.pad.Iso10126 = {
	    pad: function (data, blockSize) {
	        // Shortcut
	        var blockSizeBytes = blockSize * 4;

	        // Count padding bytes
	        var nPaddingBytes = blockSizeBytes - data.sigBytes % blockSizeBytes;

	        // Pad
	        data.concat(CryptoJS.lib.WordArray.random(nPaddingBytes - 1)).
	             concat(CryptoJS.lib.WordArray.create([nPaddingBytes << 24], 1));
	    },

	    unpad: function (data) {
	        // Get number of padding bytes from last byte
	        var nPaddingBytes = data.words[(data.sigBytes - 1) >>> 2] & 0xff;

	        // Remove padding
	        data.sigBytes -= nPaddingBytes;
	    }
	};


	return CryptoJS.pad.Iso10126;

}));

/***/ }),

/***/ "./node_modules/crypto-js/pad-iso97971.js":
/*!************************************************!*\
  !*** ./node_modules/crypto-js/pad-iso97971.js ***!
  \************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * ISO/IEC 9797-1 Padding Method 2.
	 */
	CryptoJS.pad.Iso97971 = {
	    pad: function (data, blockSize) {
	        // Add 0x80 byte
	        data.concat(CryptoJS.lib.WordArray.create([0x80000000], 1));

	        // Zero pad the rest
	        CryptoJS.pad.ZeroPadding.pad(data, blockSize);
	    },

	    unpad: function (data) {
	        // Remove zero padding
	        CryptoJS.pad.ZeroPadding.unpad(data);

	        // Remove one more byte -- the 0x80 byte
	        data.sigBytes--;
	    }
	};


	return CryptoJS.pad.Iso97971;

}));

/***/ }),

/***/ "./node_modules/crypto-js/pad-nopadding.js":
/*!*************************************************!*\
  !*** ./node_modules/crypto-js/pad-nopadding.js ***!
  \*************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * A noop padding strategy.
	 */
	CryptoJS.pad.NoPadding = {
	    pad: function () {
	    },

	    unpad: function () {
	    }
	};


	return CryptoJS.pad.NoPadding;

}));

/***/ }),

/***/ "./node_modules/crypto-js/pad-zeropadding.js":
/*!***************************************************!*\
  !*** ./node_modules/crypto-js/pad-zeropadding.js ***!
  \***************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/**
	 * Zero padding strategy.
	 */
	CryptoJS.pad.ZeroPadding = {
	    pad: function (data, blockSize) {
	        // Shortcut
	        var blockSizeBytes = blockSize * 4;

	        // Pad
	        data.clamp();
	        data.sigBytes += blockSizeBytes - ((data.sigBytes % blockSizeBytes) || blockSizeBytes);
	    },

	    unpad: function (data) {
	        // Shortcut
	        var dataWords = data.words;

	        // Unpad
	        var i = data.sigBytes - 1;
	        while (!((dataWords[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff)) {
	            i--;
	        }
	        data.sigBytes = i + 1;
	    }
	};


	return CryptoJS.pad.ZeroPadding;

}));

/***/ }),

/***/ "./node_modules/crypto-js/pbkdf2.js":
/*!******************************************!*\
  !*** ./node_modules/crypto-js/pbkdf2.js ***!
  \******************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./sha1 */ "./node_modules/crypto-js/sha1.js"), __webpack_require__(/*! ./hmac */ "./node_modules/crypto-js/hmac.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var SHA1 = C_algo.SHA1;
	    var HMAC = C_algo.HMAC;

	    /**
	     * Password-Based Key Derivation Function 2 algorithm.
	     */
	    var PBKDF2 = C_algo.PBKDF2 = Base.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} keySize The key size in words to generate. Default: 4 (128 bits)
	         * @property {Hasher} hasher The hasher to use. Default: SHA1
	         * @property {number} iterations The number of iterations to perform. Default: 1
	         */
	        cfg: Base.extend({
	            keySize: 128/32,
	            hasher: SHA1,
	            iterations: 1
	        }),

	        /**
	         * Initializes a newly created key derivation function.
	         *
	         * @param {Object} cfg (Optional) The configuration options to use for the derivation.
	         *
	         * @example
	         *
	         *     var kdf = CryptoJS.algo.PBKDF2.create();
	         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8 });
	         *     var kdf = CryptoJS.algo.PBKDF2.create({ keySize: 8, iterations: 1000 });
	         */
	        init: function (cfg) {
	            this.cfg = this.cfg.extend(cfg);
	        },

	        /**
	         * Computes the Password-Based Key Derivation Function 2.
	         *
	         * @param {WordArray|string} password The password.
	         * @param {WordArray|string} salt A salt.
	         *
	         * @return {WordArray} The derived key.
	         *
	         * @example
	         *
	         *     var key = kdf.compute(password, salt);
	         */
	        compute: function (password, salt) {
	            // Shortcut
	            var cfg = this.cfg;

	            // Init HMAC
	            var hmac = HMAC.create(cfg.hasher, password);

	            // Initial values
	            var derivedKey = WordArray.create();
	            var blockIndex = WordArray.create([0x00000001]);

	            // Shortcuts
	            var derivedKeyWords = derivedKey.words;
	            var blockIndexWords = blockIndex.words;
	            var keySize = cfg.keySize;
	            var iterations = cfg.iterations;

	            // Generate key
	            while (derivedKeyWords.length < keySize) {
	                var block = hmac.update(salt).finalize(blockIndex);
	                hmac.reset();

	                // Shortcuts
	                var blockWords = block.words;
	                var blockWordsLength = blockWords.length;

	                // Iterations
	                var intermediate = block;
	                for (var i = 1; i < iterations; i++) {
	                    intermediate = hmac.finalize(intermediate);
	                    hmac.reset();

	                    // Shortcut
	                    var intermediateWords = intermediate.words;

	                    // XOR intermediate with block
	                    for (var j = 0; j < blockWordsLength; j++) {
	                        blockWords[j] ^= intermediateWords[j];
	                    }
	                }

	                derivedKey.concat(block);
	                blockIndexWords[0]++;
	            }
	            derivedKey.sigBytes = keySize * 4;

	            return derivedKey;
	        }
	    });

	    /**
	     * Computes the Password-Based Key Derivation Function 2.
	     *
	     * @param {WordArray|string} password The password.
	     * @param {WordArray|string} salt A salt.
	     * @param {Object} cfg (Optional) The configuration options to use for this computation.
	     *
	     * @return {WordArray} The derived key.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var key = CryptoJS.PBKDF2(password, salt);
	     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8 });
	     *     var key = CryptoJS.PBKDF2(password, salt, { keySize: 8, iterations: 1000 });
	     */
	    C.PBKDF2 = function (password, salt, cfg) {
	        return PBKDF2.create(cfg).compute(password, salt);
	    };
	}());


	return CryptoJS.PBKDF2;

}));

/***/ }),

/***/ "./node_modules/crypto-js/rabbit-legacy.js":
/*!*************************************************!*\
  !*** ./node_modules/crypto-js/rabbit-legacy.js ***!
  \*************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./enc-base64 */ "./node_modules/crypto-js/enc-base64.js"), __webpack_require__(/*! ./md5 */ "./node_modules/crypto-js/md5.js"), __webpack_require__(/*! ./evpkdf */ "./node_modules/crypto-js/evpkdf.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    // Reusable objects
	    var S  = [];
	    var C_ = [];
	    var G  = [];

	    /**
	     * Rabbit stream cipher algorithm.
	     *
	     * This is a legacy version that neglected to convert the key to little-endian.
	     * This error doesn't affect the cipher's security,
	     * but it does affect its compatibility with other implementations.
	     */
	    var RabbitLegacy = C_algo.RabbitLegacy = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var K = this._key.words;
	            var iv = this.cfg.iv;

	            // Generate initial state values
	            var X = this._X = [
	                K[0], (K[3] << 16) | (K[2] >>> 16),
	                K[1], (K[0] << 16) | (K[3] >>> 16),
	                K[2], (K[1] << 16) | (K[0] >>> 16),
	                K[3], (K[2] << 16) | (K[1] >>> 16)
	            ];

	            // Generate initial counter values
	            var C = this._C = [
	                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
	                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
	                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
	                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
	            ];

	            // Carry bit
	            this._b = 0;

	            // Iterate the system four times
	            for (var i = 0; i < 4; i++) {
	                nextState.call(this);
	            }

	            // Modify the counters
	            for (var i = 0; i < 8; i++) {
	                C[i] ^= X[(i + 4) & 7];
	            }

	            // IV setup
	            if (iv) {
	                // Shortcuts
	                var IV = iv.words;
	                var IV_0 = IV[0];
	                var IV_1 = IV[1];

	                // Generate four subvectors
	                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
	                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
	                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
	                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

	                // Modify counter values
	                C[0] ^= i0;
	                C[1] ^= i1;
	                C[2] ^= i2;
	                C[3] ^= i3;
	                C[4] ^= i0;
	                C[5] ^= i1;
	                C[6] ^= i2;
	                C[7] ^= i3;

	                // Iterate the system four times
	                for (var i = 0; i < 4; i++) {
	                    nextState.call(this);
	                }
	            }
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var X = this._X;

	            // Iterate the system
	            nextState.call(this);

	            // Generate four keystream words
	            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
	            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
	            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
	            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

	            for (var i = 0; i < 4; i++) {
	                // Swap endian
	                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
	                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

	                // Encrypt
	                M[offset + i] ^= S[i];
	            }
	        },

	        blockSize: 128/32,

	        ivSize: 64/32
	    });

	    function nextState() {
	        // Shortcuts
	        var X = this._X;
	        var C = this._C;

	        // Save old counter values
	        for (var i = 0; i < 8; i++) {
	            C_[i] = C[i];
	        }

	        // Calculate new counter values
	        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
	        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
	        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
	        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
	        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
	        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
	        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
	        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
	        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

	        // Calculate the g-values
	        for (var i = 0; i < 8; i++) {
	            var gx = X[i] + C[i];

	            // Construct high and low argument for squaring
	            var ga = gx & 0xffff;
	            var gb = gx >>> 16;

	            // Calculate high and low result of squaring
	            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
	            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

	            // High XOR low
	            G[i] = gh ^ gl;
	        }

	        // Calculate new state values
	        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
	        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
	        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
	        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
	        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
	        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
	        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
	        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RabbitLegacy.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RabbitLegacy.decrypt(ciphertext, key, cfg);
	     */
	    C.RabbitLegacy = StreamCipher._createHelper(RabbitLegacy);
	}());


	return CryptoJS.RabbitLegacy;

}));

/***/ }),

/***/ "./node_modules/crypto-js/rabbit.js":
/*!******************************************!*\
  !*** ./node_modules/crypto-js/rabbit.js ***!
  \******************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./enc-base64 */ "./node_modules/crypto-js/enc-base64.js"), __webpack_require__(/*! ./md5 */ "./node_modules/crypto-js/md5.js"), __webpack_require__(/*! ./evpkdf */ "./node_modules/crypto-js/evpkdf.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    // Reusable objects
	    var S  = [];
	    var C_ = [];
	    var G  = [];

	    /**
	     * Rabbit stream cipher algorithm
	     */
	    var Rabbit = C_algo.Rabbit = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var K = this._key.words;
	            var iv = this.cfg.iv;

	            // Swap endian
	            for (var i = 0; i < 4; i++) {
	                K[i] = (((K[i] << 8)  | (K[i] >>> 24)) & 0x00ff00ff) |
	                       (((K[i] << 24) | (K[i] >>> 8))  & 0xff00ff00);
	            }

	            // Generate initial state values
	            var X = this._X = [
	                K[0], (K[3] << 16) | (K[2] >>> 16),
	                K[1], (K[0] << 16) | (K[3] >>> 16),
	                K[2], (K[1] << 16) | (K[0] >>> 16),
	                K[3], (K[2] << 16) | (K[1] >>> 16)
	            ];

	            // Generate initial counter values
	            var C = this._C = [
	                (K[2] << 16) | (K[2] >>> 16), (K[0] & 0xffff0000) | (K[1] & 0x0000ffff),
	                (K[3] << 16) | (K[3] >>> 16), (K[1] & 0xffff0000) | (K[2] & 0x0000ffff),
	                (K[0] << 16) | (K[0] >>> 16), (K[2] & 0xffff0000) | (K[3] & 0x0000ffff),
	                (K[1] << 16) | (K[1] >>> 16), (K[3] & 0xffff0000) | (K[0] & 0x0000ffff)
	            ];

	            // Carry bit
	            this._b = 0;

	            // Iterate the system four times
	            for (var i = 0; i < 4; i++) {
	                nextState.call(this);
	            }

	            // Modify the counters
	            for (var i = 0; i < 8; i++) {
	                C[i] ^= X[(i + 4) & 7];
	            }

	            // IV setup
	            if (iv) {
	                // Shortcuts
	                var IV = iv.words;
	                var IV_0 = IV[0];
	                var IV_1 = IV[1];

	                // Generate four subvectors
	                var i0 = (((IV_0 << 8) | (IV_0 >>> 24)) & 0x00ff00ff) | (((IV_0 << 24) | (IV_0 >>> 8)) & 0xff00ff00);
	                var i2 = (((IV_1 << 8) | (IV_1 >>> 24)) & 0x00ff00ff) | (((IV_1 << 24) | (IV_1 >>> 8)) & 0xff00ff00);
	                var i1 = (i0 >>> 16) | (i2 & 0xffff0000);
	                var i3 = (i2 << 16)  | (i0 & 0x0000ffff);

	                // Modify counter values
	                C[0] ^= i0;
	                C[1] ^= i1;
	                C[2] ^= i2;
	                C[3] ^= i3;
	                C[4] ^= i0;
	                C[5] ^= i1;
	                C[6] ^= i2;
	                C[7] ^= i3;

	                // Iterate the system four times
	                for (var i = 0; i < 4; i++) {
	                    nextState.call(this);
	                }
	            }
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var X = this._X;

	            // Iterate the system
	            nextState.call(this);

	            // Generate four keystream words
	            S[0] = X[0] ^ (X[5] >>> 16) ^ (X[3] << 16);
	            S[1] = X[2] ^ (X[7] >>> 16) ^ (X[5] << 16);
	            S[2] = X[4] ^ (X[1] >>> 16) ^ (X[7] << 16);
	            S[3] = X[6] ^ (X[3] >>> 16) ^ (X[1] << 16);

	            for (var i = 0; i < 4; i++) {
	                // Swap endian
	                S[i] = (((S[i] << 8)  | (S[i] >>> 24)) & 0x00ff00ff) |
	                       (((S[i] << 24) | (S[i] >>> 8))  & 0xff00ff00);

	                // Encrypt
	                M[offset + i] ^= S[i];
	            }
	        },

	        blockSize: 128/32,

	        ivSize: 64/32
	    });

	    function nextState() {
	        // Shortcuts
	        var X = this._X;
	        var C = this._C;

	        // Save old counter values
	        for (var i = 0; i < 8; i++) {
	            C_[i] = C[i];
	        }

	        // Calculate new counter values
	        C[0] = (C[0] + 0x4d34d34d + this._b) | 0;
	        C[1] = (C[1] + 0xd34d34d3 + ((C[0] >>> 0) < (C_[0] >>> 0) ? 1 : 0)) | 0;
	        C[2] = (C[2] + 0x34d34d34 + ((C[1] >>> 0) < (C_[1] >>> 0) ? 1 : 0)) | 0;
	        C[3] = (C[3] + 0x4d34d34d + ((C[2] >>> 0) < (C_[2] >>> 0) ? 1 : 0)) | 0;
	        C[4] = (C[4] + 0xd34d34d3 + ((C[3] >>> 0) < (C_[3] >>> 0) ? 1 : 0)) | 0;
	        C[5] = (C[5] + 0x34d34d34 + ((C[4] >>> 0) < (C_[4] >>> 0) ? 1 : 0)) | 0;
	        C[6] = (C[6] + 0x4d34d34d + ((C[5] >>> 0) < (C_[5] >>> 0) ? 1 : 0)) | 0;
	        C[7] = (C[7] + 0xd34d34d3 + ((C[6] >>> 0) < (C_[6] >>> 0) ? 1 : 0)) | 0;
	        this._b = (C[7] >>> 0) < (C_[7] >>> 0) ? 1 : 0;

	        // Calculate the g-values
	        for (var i = 0; i < 8; i++) {
	            var gx = X[i] + C[i];

	            // Construct high and low argument for squaring
	            var ga = gx & 0xffff;
	            var gb = gx >>> 16;

	            // Calculate high and low result of squaring
	            var gh = ((((ga * ga) >>> 17) + ga * gb) >>> 15) + gb * gb;
	            var gl = (((gx & 0xffff0000) * gx) | 0) + (((gx & 0x0000ffff) * gx) | 0);

	            // High XOR low
	            G[i] = gh ^ gl;
	        }

	        // Calculate new state values
	        X[0] = (G[0] + ((G[7] << 16) | (G[7] >>> 16)) + ((G[6] << 16) | (G[6] >>> 16))) | 0;
	        X[1] = (G[1] + ((G[0] << 8)  | (G[0] >>> 24)) + G[7]) | 0;
	        X[2] = (G[2] + ((G[1] << 16) | (G[1] >>> 16)) + ((G[0] << 16) | (G[0] >>> 16))) | 0;
	        X[3] = (G[3] + ((G[2] << 8)  | (G[2] >>> 24)) + G[1]) | 0;
	        X[4] = (G[4] + ((G[3] << 16) | (G[3] >>> 16)) + ((G[2] << 16) | (G[2] >>> 16))) | 0;
	        X[5] = (G[5] + ((G[4] << 8)  | (G[4] >>> 24)) + G[3]) | 0;
	        X[6] = (G[6] + ((G[5] << 16) | (G[5] >>> 16)) + ((G[4] << 16) | (G[4] >>> 16))) | 0;
	        X[7] = (G[7] + ((G[6] << 8)  | (G[6] >>> 24)) + G[5]) | 0;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.Rabbit.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.Rabbit.decrypt(ciphertext, key, cfg);
	     */
	    C.Rabbit = StreamCipher._createHelper(Rabbit);
	}());


	return CryptoJS.Rabbit;

}));

/***/ }),

/***/ "./node_modules/crypto-js/rc4.js":
/*!***************************************!*\
  !*** ./node_modules/crypto-js/rc4.js ***!
  \***************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./enc-base64 */ "./node_modules/crypto-js/enc-base64.js"), __webpack_require__(/*! ./md5 */ "./node_modules/crypto-js/md5.js"), __webpack_require__(/*! ./evpkdf */ "./node_modules/crypto-js/evpkdf.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var StreamCipher = C_lib.StreamCipher;
	    var C_algo = C.algo;

	    /**
	     * RC4 stream cipher algorithm.
	     */
	    var RC4 = C_algo.RC4 = StreamCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;
	            var keySigBytes = key.sigBytes;

	            // Init sbox
	            var S = this._S = [];
	            for (var i = 0; i < 256; i++) {
	                S[i] = i;
	            }

	            // Key setup
	            for (var i = 0, j = 0; i < 256; i++) {
	                var keyByteIndex = i % keySigBytes;
	                var keyByte = (keyWords[keyByteIndex >>> 2] >>> (24 - (keyByteIndex % 4) * 8)) & 0xff;

	                j = (j + S[i] + keyByte) % 256;

	                // Swap
	                var t = S[i];
	                S[i] = S[j];
	                S[j] = t;
	            }

	            // Counters
	            this._i = this._j = 0;
	        },

	        _doProcessBlock: function (M, offset) {
	            M[offset] ^= generateKeystreamWord.call(this);
	        },

	        keySize: 256/32,

	        ivSize: 0
	    });

	    function generateKeystreamWord() {
	        // Shortcuts
	        var S = this._S;
	        var i = this._i;
	        var j = this._j;

	        // Generate keystream word
	        var keystreamWord = 0;
	        for (var n = 0; n < 4; n++) {
	            i = (i + 1) % 256;
	            j = (j + S[i]) % 256;

	            // Swap
	            var t = S[i];
	            S[i] = S[j];
	            S[j] = t;

	            keystreamWord |= S[(S[i] + S[j]) % 256] << (24 - n * 8);
	        }

	        // Update counters
	        this._i = i;
	        this._j = j;

	        return keystreamWord;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RC4.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RC4.decrypt(ciphertext, key, cfg);
	     */
	    C.RC4 = StreamCipher._createHelper(RC4);

	    /**
	     * Modified RC4 stream cipher algorithm.
	     */
	    var RC4Drop = C_algo.RC4Drop = RC4.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} drop The number of keystream words to drop. Default 192
	         */
	        cfg: RC4.cfg.extend({
	            drop: 192
	        }),

	        _doReset: function () {
	            RC4._doReset.call(this);

	            // Drop
	            for (var i = this.cfg.drop; i > 0; i--) {
	                generateKeystreamWord.call(this);
	            }
	        }
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.RC4Drop.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.RC4Drop.decrypt(ciphertext, key, cfg);
	     */
	    C.RC4Drop = StreamCipher._createHelper(RC4Drop);
	}());


	return CryptoJS.RC4;

}));

/***/ }),

/***/ "./node_modules/crypto-js/ripemd160.js":
/*!*********************************************!*\
  !*** ./node_modules/crypto-js/ripemd160.js ***!
  \*********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	/** @preserve
	(c) 2012 by Cédric Mesnil. All rights reserved.

	Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

	    - Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	    - Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
	*/

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Constants table
	    var _zl = WordArray.create([
	        0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	        7,  4, 13,  1, 10,  6, 15,  3, 12,  0,  9,  5,  2, 14, 11,  8,
	        3, 10, 14,  4,  9, 15,  8,  1,  2,  7,  0,  6, 13, 11,  5, 12,
	        1,  9, 11, 10,  0,  8, 12,  4, 13,  3,  7, 15, 14,  5,  6,  2,
	        4,  0,  5,  9,  7, 12,  2, 10, 14,  1,  3,  8, 11,  6, 15, 13]);
	    var _zr = WordArray.create([
	        5, 14,  7,  0,  9,  2, 11,  4, 13,  6, 15,  8,  1, 10,  3, 12,
	        6, 11,  3,  7,  0, 13,  5, 10, 14, 15,  8, 12,  4,  9,  1,  2,
	        15,  5,  1,  3,  7, 14,  6,  9, 11,  8, 12,  2, 10,  0,  4, 13,
	        8,  6,  4,  1,  3, 11, 15,  0,  5, 12,  2, 13,  9,  7, 10, 14,
	        12, 15, 10,  4,  1,  5,  8,  7,  6,  2, 13, 14,  0,  3,  9, 11]);
	    var _sl = WordArray.create([
	         11, 14, 15, 12,  5,  8,  7,  9, 11, 13, 14, 15,  6,  7,  9,  8,
	        7, 6,   8, 13, 11,  9,  7, 15,  7, 12, 15,  9, 11,  7, 13, 12,
	        11, 13,  6,  7, 14,  9, 13, 15, 14,  8, 13,  6,  5, 12,  7,  5,
	          11, 12, 14, 15, 14, 15,  9,  8,  9, 14,  5,  6,  8,  6,  5, 12,
	        9, 15,  5, 11,  6,  8, 13, 12,  5, 12, 13, 14, 11,  8,  5,  6 ]);
	    var _sr = WordArray.create([
	        8,  9,  9, 11, 13, 15, 15,  5,  7,  7,  8, 11, 14, 14, 12,  6,
	        9, 13, 15,  7, 12,  8,  9, 11,  7,  7, 12,  7,  6, 15, 13, 11,
	        9,  7, 15, 11,  8,  6,  6, 14, 12, 13,  5, 14, 13, 13,  7,  5,
	        15,  5,  8, 11, 14, 14,  6, 14,  6,  9, 12,  9, 12,  5, 15,  8,
	        8,  5, 12,  9, 12,  5, 14,  6,  8, 13,  6,  5, 15, 13, 11, 11 ]);

	    var _hl =  WordArray.create([ 0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]);
	    var _hr =  WordArray.create([ 0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]);

	    /**
	     * RIPEMD160 hash algorithm.
	     */
	    var RIPEMD160 = C_algo.RIPEMD160 = Hasher.extend({
	        _doReset: function () {
	            this._hash  = WordArray.create([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);
	        },

	        _doProcessBlock: function (M, offset) {

	            // Swap endian
	            for (var i = 0; i < 16; i++) {
	                // Shortcuts
	                var offset_i = offset + i;
	                var M_offset_i = M[offset_i];

	                // Swap
	                M[offset_i] = (
	                    (((M_offset_i << 8)  | (M_offset_i >>> 24)) & 0x00ff00ff) |
	                    (((M_offset_i << 24) | (M_offset_i >>> 8))  & 0xff00ff00)
	                );
	            }
	            // Shortcut
	            var H  = this._hash.words;
	            var hl = _hl.words;
	            var hr = _hr.words;
	            var zl = _zl.words;
	            var zr = _zr.words;
	            var sl = _sl.words;
	            var sr = _sr.words;

	            // Working variables
	            var al, bl, cl, dl, el;
	            var ar, br, cr, dr, er;

	            ar = al = H[0];
	            br = bl = H[1];
	            cr = cl = H[2];
	            dr = dl = H[3];
	            er = el = H[4];
	            // Computation
	            var t;
	            for (var i = 0; i < 80; i += 1) {
	                t = (al +  M[offset+zl[i]])|0;
	                if (i<16){
		            t +=  f1(bl,cl,dl) + hl[0];
	                } else if (i<32) {
		            t +=  f2(bl,cl,dl) + hl[1];
	                } else if (i<48) {
		            t +=  f3(bl,cl,dl) + hl[2];
	                } else if (i<64) {
		            t +=  f4(bl,cl,dl) + hl[3];
	                } else {// if (i<80) {
		            t +=  f5(bl,cl,dl) + hl[4];
	                }
	                t = t|0;
	                t =  rotl(t,sl[i]);
	                t = (t+el)|0;
	                al = el;
	                el = dl;
	                dl = rotl(cl, 10);
	                cl = bl;
	                bl = t;

	                t = (ar + M[offset+zr[i]])|0;
	                if (i<16){
		            t +=  f5(br,cr,dr) + hr[0];
	                } else if (i<32) {
		            t +=  f4(br,cr,dr) + hr[1];
	                } else if (i<48) {
		            t +=  f3(br,cr,dr) + hr[2];
	                } else if (i<64) {
		            t +=  f2(br,cr,dr) + hr[3];
	                } else {// if (i<80) {
		            t +=  f1(br,cr,dr) + hr[4];
	                }
	                t = t|0;
	                t =  rotl(t,sr[i]) ;
	                t = (t+er)|0;
	                ar = er;
	                er = dr;
	                dr = rotl(cr, 10);
	                cr = br;
	                br = t;
	            }
	            // Intermediate hash value
	            t    = (H[1] + cl + dr)|0;
	            H[1] = (H[2] + dl + er)|0;
	            H[2] = (H[3] + el + ar)|0;
	            H[3] = (H[4] + al + br)|0;
	            H[4] = (H[0] + bl + cr)|0;
	            H[0] =  t;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = (
	                (((nBitsTotal << 8)  | (nBitsTotal >>> 24)) & 0x00ff00ff) |
	                (((nBitsTotal << 24) | (nBitsTotal >>> 8))  & 0xff00ff00)
	            );
	            data.sigBytes = (dataWords.length + 1) * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var hash = this._hash;
	            var H = hash.words;

	            // Swap endian
	            for (var i = 0; i < 5; i++) {
	                // Shortcut
	                var H_i = H[i];

	                // Swap
	                H[i] = (((H_i << 8)  | (H_i >>> 24)) & 0x00ff00ff) |
	                       (((H_i << 24) | (H_i >>> 8))  & 0xff00ff00);
	            }

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });


	    function f1(x, y, z) {
	        return ((x) ^ (y) ^ (z));

	    }

	    function f2(x, y, z) {
	        return (((x)&(y)) | ((~x)&(z)));
	    }

	    function f3(x, y, z) {
	        return (((x) | (~(y))) ^ (z));
	    }

	    function f4(x, y, z) {
	        return (((x) & (z)) | ((y)&(~(z))));
	    }

	    function f5(x, y, z) {
	        return ((x) ^ ((y) |(~(z))));

	    }

	    function rotl(x,n) {
	        return (x<<n) | (x>>>(32-n));
	    }


	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.RIPEMD160('message');
	     *     var hash = CryptoJS.RIPEMD160(wordArray);
	     */
	    C.RIPEMD160 = Hasher._createHelper(RIPEMD160);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacRIPEMD160(message, key);
	     */
	    C.HmacRIPEMD160 = Hasher._createHmacHelper(RIPEMD160);
	}(Math));


	return CryptoJS.RIPEMD160;

}));

/***/ }),

/***/ "./node_modules/crypto-js/sha1.js":
/*!****************************************!*\
  !*** ./node_modules/crypto-js/sha1.js ***!
  \****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Reusable object
	    var W = [];

	    /**
	     * SHA-1 hash algorithm.
	     */
	    var SHA1 = C_algo.SHA1 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0x67452301, 0xefcdab89,
	                0x98badcfe, 0x10325476,
	                0xc3d2e1f0
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var H = this._hash.words;

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];
	            var e = H[4];

	            // Computation
	            for (var i = 0; i < 80; i++) {
	                if (i < 16) {
	                    W[i] = M[offset + i] | 0;
	                } else {
	                    var n = W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16];
	                    W[i] = (n << 1) | (n >>> 31);
	                }

	                var t = ((a << 5) | (a >>> 27)) + e + W[i];
	                if (i < 20) {
	                    t += ((b & c) | (~b & d)) + 0x5a827999;
	                } else if (i < 40) {
	                    t += (b ^ c ^ d) + 0x6ed9eba1;
	                } else if (i < 60) {
	                    t += ((b & c) | (b & d) | (c & d)) - 0x70e44324;
	                } else /* if (i < 80) */ {
	                    t += (b ^ c ^ d) - 0x359d3e2a;
	                }

	                e = d;
	                d = c;
	                c = (b << 30) | (b >>> 2);
	                b = a;
	                a = t;
	            }

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	            H[4] = (H[4] + e) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Return final computed hash
	            return this._hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA1('message');
	     *     var hash = CryptoJS.SHA1(wordArray);
	     */
	    C.SHA1 = Hasher._createHelper(SHA1);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA1(message, key);
	     */
	    C.HmacSHA1 = Hasher._createHmacHelper(SHA1);
	}());


	return CryptoJS.SHA1;

}));

/***/ }),

/***/ "./node_modules/crypto-js/sha224.js":
/*!******************************************!*\
  !*** ./node_modules/crypto-js/sha224.js ***!
  \******************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./sha256 */ "./node_modules/crypto-js/sha256.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var C_algo = C.algo;
	    var SHA256 = C_algo.SHA256;

	    /**
	     * SHA-224 hash algorithm.
	     */
	    var SHA224 = C_algo.SHA224 = SHA256.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init([
	                0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
	                0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
	            ]);
	        },

	        _doFinalize: function () {
	            var hash = SHA256._doFinalize.call(this);

	            hash.sigBytes -= 4;

	            return hash;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA224('message');
	     *     var hash = CryptoJS.SHA224(wordArray);
	     */
	    C.SHA224 = SHA256._createHelper(SHA224);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA224(message, key);
	     */
	    C.HmacSHA224 = SHA256._createHmacHelper(SHA224);
	}());


	return CryptoJS.SHA224;

}));

/***/ }),

/***/ "./node_modules/crypto-js/sha256.js":
/*!******************************************!*\
  !*** ./node_modules/crypto-js/sha256.js ***!
  \******************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_algo = C.algo;

	    // Initialization and round constants tables
	    var H = [];
	    var K = [];

	    // Compute constants
	    (function () {
	        function isPrime(n) {
	            var sqrtN = Math.sqrt(n);
	            for (var factor = 2; factor <= sqrtN; factor++) {
	                if (!(n % factor)) {
	                    return false;
	                }
	            }

	            return true;
	        }

	        function getFractionalBits(n) {
	            return ((n - (n | 0)) * 0x100000000) | 0;
	        }

	        var n = 2;
	        var nPrime = 0;
	        while (nPrime < 64) {
	            if (isPrime(n)) {
	                if (nPrime < 8) {
	                    H[nPrime] = getFractionalBits(Math.pow(n, 1 / 2));
	                }
	                K[nPrime] = getFractionalBits(Math.pow(n, 1 / 3));

	                nPrime++;
	            }

	            n++;
	        }
	    }());

	    // Reusable object
	    var W = [];

	    /**
	     * SHA-256 hash algorithm.
	     */
	    var SHA256 = C_algo.SHA256 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new WordArray.init(H.slice(0));
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcut
	            var H = this._hash.words;

	            // Working variables
	            var a = H[0];
	            var b = H[1];
	            var c = H[2];
	            var d = H[3];
	            var e = H[4];
	            var f = H[5];
	            var g = H[6];
	            var h = H[7];

	            // Computation
	            for (var i = 0; i < 64; i++) {
	                if (i < 16) {
	                    W[i] = M[offset + i] | 0;
	                } else {
	                    var gamma0x = W[i - 15];
	                    var gamma0  = ((gamma0x << 25) | (gamma0x >>> 7))  ^
	                                  ((gamma0x << 14) | (gamma0x >>> 18)) ^
	                                   (gamma0x >>> 3);

	                    var gamma1x = W[i - 2];
	                    var gamma1  = ((gamma1x << 15) | (gamma1x >>> 17)) ^
	                                  ((gamma1x << 13) | (gamma1x >>> 19)) ^
	                                   (gamma1x >>> 10);

	                    W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16];
	                }

	                var ch  = (e & f) ^ (~e & g);
	                var maj = (a & b) ^ (a & c) ^ (b & c);

	                var sigma0 = ((a << 30) | (a >>> 2)) ^ ((a << 19) | (a >>> 13)) ^ ((a << 10) | (a >>> 22));
	                var sigma1 = ((e << 26) | (e >>> 6)) ^ ((e << 21) | (e >>> 11)) ^ ((e << 7)  | (e >>> 25));

	                var t1 = h + sigma1 + ch + K[i] + W[i];
	                var t2 = sigma0 + maj;

	                h = g;
	                g = f;
	                f = e;
	                e = (d + t1) | 0;
	                d = c;
	                c = b;
	                b = a;
	                a = (t1 + t2) | 0;
	            }

	            // Intermediate hash value
	            H[0] = (H[0] + a) | 0;
	            H[1] = (H[1] + b) | 0;
	            H[2] = (H[2] + c) | 0;
	            H[3] = (H[3] + d) | 0;
	            H[4] = (H[4] + e) | 0;
	            H[5] = (H[5] + f) | 0;
	            H[6] = (H[6] + g) | 0;
	            H[7] = (H[7] + h) | 0;
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Return final computed hash
	            return this._hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA256('message');
	     *     var hash = CryptoJS.SHA256(wordArray);
	     */
	    C.SHA256 = Hasher._createHelper(SHA256);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA256(message, key);
	     */
	    C.HmacSHA256 = Hasher._createHmacHelper(SHA256);
	}(Math));


	return CryptoJS.SHA256;

}));

/***/ }),

/***/ "./node_modules/crypto-js/sha3.js":
/*!****************************************!*\
  !*** ./node_modules/crypto-js/sha3.js ***!
  \****************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./x64-core */ "./node_modules/crypto-js/x64-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function (Math) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var Hasher = C_lib.Hasher;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var C_algo = C.algo;

	    // Constants tables
	    var RHO_OFFSETS = [];
	    var PI_INDEXES  = [];
	    var ROUND_CONSTANTS = [];

	    // Compute Constants
	    (function () {
	        // Compute rho offset constants
	        var x = 1, y = 0;
	        for (var t = 0; t < 24; t++) {
	            RHO_OFFSETS[x + 5 * y] = ((t + 1) * (t + 2) / 2) % 64;

	            var newX = y % 5;
	            var newY = (2 * x + 3 * y) % 5;
	            x = newX;
	            y = newY;
	        }

	        // Compute pi index constants
	        for (var x = 0; x < 5; x++) {
	            for (var y = 0; y < 5; y++) {
	                PI_INDEXES[x + 5 * y] = y + ((2 * x + 3 * y) % 5) * 5;
	            }
	        }

	        // Compute round constants
	        var LFSR = 0x01;
	        for (var i = 0; i < 24; i++) {
	            var roundConstantMsw = 0;
	            var roundConstantLsw = 0;

	            for (var j = 0; j < 7; j++) {
	                if (LFSR & 0x01) {
	                    var bitPosition = (1 << j) - 1;
	                    if (bitPosition < 32) {
	                        roundConstantLsw ^= 1 << bitPosition;
	                    } else /* if (bitPosition >= 32) */ {
	                        roundConstantMsw ^= 1 << (bitPosition - 32);
	                    }
	                }

	                // Compute next LFSR
	                if (LFSR & 0x80) {
	                    // Primitive polynomial over GF(2): x^8 + x^6 + x^5 + x^4 + 1
	                    LFSR = (LFSR << 1) ^ 0x71;
	                } else {
	                    LFSR <<= 1;
	                }
	            }

	            ROUND_CONSTANTS[i] = X64Word.create(roundConstantMsw, roundConstantLsw);
	        }
	    }());

	    // Reusable objects for temporary values
	    var T = [];
	    (function () {
	        for (var i = 0; i < 25; i++) {
	            T[i] = X64Word.create();
	        }
	    }());

	    /**
	     * SHA-3 hash algorithm.
	     */
	    var SHA3 = C_algo.SHA3 = Hasher.extend({
	        /**
	         * Configuration options.
	         *
	         * @property {number} outputLength
	         *   The desired number of bits in the output hash.
	         *   Only values permitted are: 224, 256, 384, 512.
	         *   Default: 512
	         */
	        cfg: Hasher.cfg.extend({
	            outputLength: 512
	        }),

	        _doReset: function () {
	            var state = this._state = []
	            for (var i = 0; i < 25; i++) {
	                state[i] = new X64Word.init();
	            }

	            this.blockSize = (1600 - 2 * this.cfg.outputLength) / 32;
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcuts
	            var state = this._state;
	            var nBlockSizeLanes = this.blockSize / 2;

	            // Absorb
	            for (var i = 0; i < nBlockSizeLanes; i++) {
	                // Shortcuts
	                var M2i  = M[offset + 2 * i];
	                var M2i1 = M[offset + 2 * i + 1];

	                // Swap endian
	                M2i = (
	                    (((M2i << 8)  | (M2i >>> 24)) & 0x00ff00ff) |
	                    (((M2i << 24) | (M2i >>> 8))  & 0xff00ff00)
	                );
	                M2i1 = (
	                    (((M2i1 << 8)  | (M2i1 >>> 24)) & 0x00ff00ff) |
	                    (((M2i1 << 24) | (M2i1 >>> 8))  & 0xff00ff00)
	                );

	                // Absorb message into state
	                var lane = state[i];
	                lane.high ^= M2i1;
	                lane.low  ^= M2i;
	            }

	            // Rounds
	            for (var round = 0; round < 24; round++) {
	                // Theta
	                for (var x = 0; x < 5; x++) {
	                    // Mix column lanes
	                    var tMsw = 0, tLsw = 0;
	                    for (var y = 0; y < 5; y++) {
	                        var lane = state[x + 5 * y];
	                        tMsw ^= lane.high;
	                        tLsw ^= lane.low;
	                    }

	                    // Temporary values
	                    var Tx = T[x];
	                    Tx.high = tMsw;
	                    Tx.low  = tLsw;
	                }
	                for (var x = 0; x < 5; x++) {
	                    // Shortcuts
	                    var Tx4 = T[(x + 4) % 5];
	                    var Tx1 = T[(x + 1) % 5];
	                    var Tx1Msw = Tx1.high;
	                    var Tx1Lsw = Tx1.low;

	                    // Mix surrounding columns
	                    var tMsw = Tx4.high ^ ((Tx1Msw << 1) | (Tx1Lsw >>> 31));
	                    var tLsw = Tx4.low  ^ ((Tx1Lsw << 1) | (Tx1Msw >>> 31));
	                    for (var y = 0; y < 5; y++) {
	                        var lane = state[x + 5 * y];
	                        lane.high ^= tMsw;
	                        lane.low  ^= tLsw;
	                    }
	                }

	                // Rho Pi
	                for (var laneIndex = 1; laneIndex < 25; laneIndex++) {
	                    // Shortcuts
	                    var lane = state[laneIndex];
	                    var laneMsw = lane.high;
	                    var laneLsw = lane.low;
	                    var rhoOffset = RHO_OFFSETS[laneIndex];

	                    // Rotate lanes
	                    if (rhoOffset < 32) {
	                        var tMsw = (laneMsw << rhoOffset) | (laneLsw >>> (32 - rhoOffset));
	                        var tLsw = (laneLsw << rhoOffset) | (laneMsw >>> (32 - rhoOffset));
	                    } else /* if (rhoOffset >= 32) */ {
	                        var tMsw = (laneLsw << (rhoOffset - 32)) | (laneMsw >>> (64 - rhoOffset));
	                        var tLsw = (laneMsw << (rhoOffset - 32)) | (laneLsw >>> (64 - rhoOffset));
	                    }

	                    // Transpose lanes
	                    var TPiLane = T[PI_INDEXES[laneIndex]];
	                    TPiLane.high = tMsw;
	                    TPiLane.low  = tLsw;
	                }

	                // Rho pi at x = y = 0
	                var T0 = T[0];
	                var state0 = state[0];
	                T0.high = state0.high;
	                T0.low  = state0.low;

	                // Chi
	                for (var x = 0; x < 5; x++) {
	                    for (var y = 0; y < 5; y++) {
	                        // Shortcuts
	                        var laneIndex = x + 5 * y;
	                        var lane = state[laneIndex];
	                        var TLane = T[laneIndex];
	                        var Tx1Lane = T[((x + 1) % 5) + 5 * y];
	                        var Tx2Lane = T[((x + 2) % 5) + 5 * y];

	                        // Mix rows
	                        lane.high = TLane.high ^ (~Tx1Lane.high & Tx2Lane.high);
	                        lane.low  = TLane.low  ^ (~Tx1Lane.low  & Tx2Lane.low);
	                    }
	                }

	                // Iota
	                var lane = state[0];
	                var roundConstant = ROUND_CONSTANTS[round];
	                lane.high ^= roundConstant.high;
	                lane.low  ^= roundConstant.low;;
	            }
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;
	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;
	            var blockSizeBits = this.blockSize * 32;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x1 << (24 - nBitsLeft % 32);
	            dataWords[((Math.ceil((nBitsLeft + 1) / blockSizeBits) * blockSizeBits) >>> 5) - 1] |= 0x80;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Shortcuts
	            var state = this._state;
	            var outputLengthBytes = this.cfg.outputLength / 8;
	            var outputLengthLanes = outputLengthBytes / 8;

	            // Squeeze
	            var hashWords = [];
	            for (var i = 0; i < outputLengthLanes; i++) {
	                // Shortcuts
	                var lane = state[i];
	                var laneMsw = lane.high;
	                var laneLsw = lane.low;

	                // Swap endian
	                laneMsw = (
	                    (((laneMsw << 8)  | (laneMsw >>> 24)) & 0x00ff00ff) |
	                    (((laneMsw << 24) | (laneMsw >>> 8))  & 0xff00ff00)
	                );
	                laneLsw = (
	                    (((laneLsw << 8)  | (laneLsw >>> 24)) & 0x00ff00ff) |
	                    (((laneLsw << 24) | (laneLsw >>> 8))  & 0xff00ff00)
	                );

	                // Squeeze state to retrieve hash
	                hashWords.push(laneLsw);
	                hashWords.push(laneMsw);
	            }

	            // Return final computed hash
	            return new WordArray.init(hashWords, outputLengthBytes);
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);

	            var state = clone._state = this._state.slice(0);
	            for (var i = 0; i < 25; i++) {
	                state[i] = state[i].clone();
	            }

	            return clone;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA3('message');
	     *     var hash = CryptoJS.SHA3(wordArray);
	     */
	    C.SHA3 = Hasher._createHelper(SHA3);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA3(message, key);
	     */
	    C.HmacSHA3 = Hasher._createHmacHelper(SHA3);
	}(Math));


	return CryptoJS.SHA3;

}));

/***/ }),

/***/ "./node_modules/crypto-js/sha384.js":
/*!******************************************!*\
  !*** ./node_modules/crypto-js/sha384.js ***!
  \******************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./x64-core */ "./node_modules/crypto-js/x64-core.js"), __webpack_require__(/*! ./sha512 */ "./node_modules/crypto-js/sha512.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var X64WordArray = C_x64.WordArray;
	    var C_algo = C.algo;
	    var SHA512 = C_algo.SHA512;

	    /**
	     * SHA-384 hash algorithm.
	     */
	    var SHA384 = C_algo.SHA384 = SHA512.extend({
	        _doReset: function () {
	            this._hash = new X64WordArray.init([
	                new X64Word.init(0xcbbb9d5d, 0xc1059ed8), new X64Word.init(0x629a292a, 0x367cd507),
	                new X64Word.init(0x9159015a, 0x3070dd17), new X64Word.init(0x152fecd8, 0xf70e5939),
	                new X64Word.init(0x67332667, 0xffc00b31), new X64Word.init(0x8eb44a87, 0x68581511),
	                new X64Word.init(0xdb0c2e0d, 0x64f98fa7), new X64Word.init(0x47b5481d, 0xbefa4fa4)
	            ]);
	        },

	        _doFinalize: function () {
	            var hash = SHA512._doFinalize.call(this);

	            hash.sigBytes -= 16;

	            return hash;
	        }
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA384('message');
	     *     var hash = CryptoJS.SHA384(wordArray);
	     */
	    C.SHA384 = SHA512._createHelper(SHA384);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA384(message, key);
	     */
	    C.HmacSHA384 = SHA512._createHmacHelper(SHA384);
	}());


	return CryptoJS.SHA384;

}));

/***/ }),

/***/ "./node_modules/crypto-js/sha512.js":
/*!******************************************!*\
  !*** ./node_modules/crypto-js/sha512.js ***!
  \******************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./x64-core */ "./node_modules/crypto-js/x64-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Hasher = C_lib.Hasher;
	    var C_x64 = C.x64;
	    var X64Word = C_x64.Word;
	    var X64WordArray = C_x64.WordArray;
	    var C_algo = C.algo;

	    function X64Word_create() {
	        return X64Word.create.apply(X64Word, arguments);
	    }

	    // Constants
	    var K = [
	        X64Word_create(0x428a2f98, 0xd728ae22), X64Word_create(0x71374491, 0x23ef65cd),
	        X64Word_create(0xb5c0fbcf, 0xec4d3b2f), X64Word_create(0xe9b5dba5, 0x8189dbbc),
	        X64Word_create(0x3956c25b, 0xf348b538), X64Word_create(0x59f111f1, 0xb605d019),
	        X64Word_create(0x923f82a4, 0xaf194f9b), X64Word_create(0xab1c5ed5, 0xda6d8118),
	        X64Word_create(0xd807aa98, 0xa3030242), X64Word_create(0x12835b01, 0x45706fbe),
	        X64Word_create(0x243185be, 0x4ee4b28c), X64Word_create(0x550c7dc3, 0xd5ffb4e2),
	        X64Word_create(0x72be5d74, 0xf27b896f), X64Word_create(0x80deb1fe, 0x3b1696b1),
	        X64Word_create(0x9bdc06a7, 0x25c71235), X64Word_create(0xc19bf174, 0xcf692694),
	        X64Word_create(0xe49b69c1, 0x9ef14ad2), X64Word_create(0xefbe4786, 0x384f25e3),
	        X64Word_create(0x0fc19dc6, 0x8b8cd5b5), X64Word_create(0x240ca1cc, 0x77ac9c65),
	        X64Word_create(0x2de92c6f, 0x592b0275), X64Word_create(0x4a7484aa, 0x6ea6e483),
	        X64Word_create(0x5cb0a9dc, 0xbd41fbd4), X64Word_create(0x76f988da, 0x831153b5),
	        X64Word_create(0x983e5152, 0xee66dfab), X64Word_create(0xa831c66d, 0x2db43210),
	        X64Word_create(0xb00327c8, 0x98fb213f), X64Word_create(0xbf597fc7, 0xbeef0ee4),
	        X64Word_create(0xc6e00bf3, 0x3da88fc2), X64Word_create(0xd5a79147, 0x930aa725),
	        X64Word_create(0x06ca6351, 0xe003826f), X64Word_create(0x14292967, 0x0a0e6e70),
	        X64Word_create(0x27b70a85, 0x46d22ffc), X64Word_create(0x2e1b2138, 0x5c26c926),
	        X64Word_create(0x4d2c6dfc, 0x5ac42aed), X64Word_create(0x53380d13, 0x9d95b3df),
	        X64Word_create(0x650a7354, 0x8baf63de), X64Word_create(0x766a0abb, 0x3c77b2a8),
	        X64Word_create(0x81c2c92e, 0x47edaee6), X64Word_create(0x92722c85, 0x1482353b),
	        X64Word_create(0xa2bfe8a1, 0x4cf10364), X64Word_create(0xa81a664b, 0xbc423001),
	        X64Word_create(0xc24b8b70, 0xd0f89791), X64Word_create(0xc76c51a3, 0x0654be30),
	        X64Word_create(0xd192e819, 0xd6ef5218), X64Word_create(0xd6990624, 0x5565a910),
	        X64Word_create(0xf40e3585, 0x5771202a), X64Word_create(0x106aa070, 0x32bbd1b8),
	        X64Word_create(0x19a4c116, 0xb8d2d0c8), X64Word_create(0x1e376c08, 0x5141ab53),
	        X64Word_create(0x2748774c, 0xdf8eeb99), X64Word_create(0x34b0bcb5, 0xe19b48a8),
	        X64Word_create(0x391c0cb3, 0xc5c95a63), X64Word_create(0x4ed8aa4a, 0xe3418acb),
	        X64Word_create(0x5b9cca4f, 0x7763e373), X64Word_create(0x682e6ff3, 0xd6b2b8a3),
	        X64Word_create(0x748f82ee, 0x5defb2fc), X64Word_create(0x78a5636f, 0x43172f60),
	        X64Word_create(0x84c87814, 0xa1f0ab72), X64Word_create(0x8cc70208, 0x1a6439ec),
	        X64Word_create(0x90befffa, 0x23631e28), X64Word_create(0xa4506ceb, 0xde82bde9),
	        X64Word_create(0xbef9a3f7, 0xb2c67915), X64Word_create(0xc67178f2, 0xe372532b),
	        X64Word_create(0xca273ece, 0xea26619c), X64Word_create(0xd186b8c7, 0x21c0c207),
	        X64Word_create(0xeada7dd6, 0xcde0eb1e), X64Word_create(0xf57d4f7f, 0xee6ed178),
	        X64Word_create(0x06f067aa, 0x72176fba), X64Word_create(0x0a637dc5, 0xa2c898a6),
	        X64Word_create(0x113f9804, 0xbef90dae), X64Word_create(0x1b710b35, 0x131c471b),
	        X64Word_create(0x28db77f5, 0x23047d84), X64Word_create(0x32caab7b, 0x40c72493),
	        X64Word_create(0x3c9ebe0a, 0x15c9bebc), X64Word_create(0x431d67c4, 0x9c100d4c),
	        X64Word_create(0x4cc5d4be, 0xcb3e42b6), X64Word_create(0x597f299c, 0xfc657e2a),
	        X64Word_create(0x5fcb6fab, 0x3ad6faec), X64Word_create(0x6c44198c, 0x4a475817)
	    ];

	    // Reusable objects
	    var W = [];
	    (function () {
	        for (var i = 0; i < 80; i++) {
	            W[i] = X64Word_create();
	        }
	    }());

	    /**
	     * SHA-512 hash algorithm.
	     */
	    var SHA512 = C_algo.SHA512 = Hasher.extend({
	        _doReset: function () {
	            this._hash = new X64WordArray.init([
	                new X64Word.init(0x6a09e667, 0xf3bcc908), new X64Word.init(0xbb67ae85, 0x84caa73b),
	                new X64Word.init(0x3c6ef372, 0xfe94f82b), new X64Word.init(0xa54ff53a, 0x5f1d36f1),
	                new X64Word.init(0x510e527f, 0xade682d1), new X64Word.init(0x9b05688c, 0x2b3e6c1f),
	                new X64Word.init(0x1f83d9ab, 0xfb41bd6b), new X64Word.init(0x5be0cd19, 0x137e2179)
	            ]);
	        },

	        _doProcessBlock: function (M, offset) {
	            // Shortcuts
	            var H = this._hash.words;

	            var H0 = H[0];
	            var H1 = H[1];
	            var H2 = H[2];
	            var H3 = H[3];
	            var H4 = H[4];
	            var H5 = H[5];
	            var H6 = H[6];
	            var H7 = H[7];

	            var H0h = H0.high;
	            var H0l = H0.low;
	            var H1h = H1.high;
	            var H1l = H1.low;
	            var H2h = H2.high;
	            var H2l = H2.low;
	            var H3h = H3.high;
	            var H3l = H3.low;
	            var H4h = H4.high;
	            var H4l = H4.low;
	            var H5h = H5.high;
	            var H5l = H5.low;
	            var H6h = H6.high;
	            var H6l = H6.low;
	            var H7h = H7.high;
	            var H7l = H7.low;

	            // Working variables
	            var ah = H0h;
	            var al = H0l;
	            var bh = H1h;
	            var bl = H1l;
	            var ch = H2h;
	            var cl = H2l;
	            var dh = H3h;
	            var dl = H3l;
	            var eh = H4h;
	            var el = H4l;
	            var fh = H5h;
	            var fl = H5l;
	            var gh = H6h;
	            var gl = H6l;
	            var hh = H7h;
	            var hl = H7l;

	            // Rounds
	            for (var i = 0; i < 80; i++) {
	                // Shortcut
	                var Wi = W[i];

	                // Extend message
	                if (i < 16) {
	                    var Wih = Wi.high = M[offset + i * 2]     | 0;
	                    var Wil = Wi.low  = M[offset + i * 2 + 1] | 0;
	                } else {
	                    // Gamma0
	                    var gamma0x  = W[i - 15];
	                    var gamma0xh = gamma0x.high;
	                    var gamma0xl = gamma0x.low;
	                    var gamma0h  = ((gamma0xh >>> 1) | (gamma0xl << 31)) ^ ((gamma0xh >>> 8) | (gamma0xl << 24)) ^ (gamma0xh >>> 7);
	                    var gamma0l  = ((gamma0xl >>> 1) | (gamma0xh << 31)) ^ ((gamma0xl >>> 8) | (gamma0xh << 24)) ^ ((gamma0xl >>> 7) | (gamma0xh << 25));

	                    // Gamma1
	                    var gamma1x  = W[i - 2];
	                    var gamma1xh = gamma1x.high;
	                    var gamma1xl = gamma1x.low;
	                    var gamma1h  = ((gamma1xh >>> 19) | (gamma1xl << 13)) ^ ((gamma1xh << 3) | (gamma1xl >>> 29)) ^ (gamma1xh >>> 6);
	                    var gamma1l  = ((gamma1xl >>> 19) | (gamma1xh << 13)) ^ ((gamma1xl << 3) | (gamma1xh >>> 29)) ^ ((gamma1xl >>> 6) | (gamma1xh << 26));

	                    // W[i] = gamma0 + W[i - 7] + gamma1 + W[i - 16]
	                    var Wi7  = W[i - 7];
	                    var Wi7h = Wi7.high;
	                    var Wi7l = Wi7.low;

	                    var Wi16  = W[i - 16];
	                    var Wi16h = Wi16.high;
	                    var Wi16l = Wi16.low;

	                    var Wil = gamma0l + Wi7l;
	                    var Wih = gamma0h + Wi7h + ((Wil >>> 0) < (gamma0l >>> 0) ? 1 : 0);
	                    var Wil = Wil + gamma1l;
	                    var Wih = Wih + gamma1h + ((Wil >>> 0) < (gamma1l >>> 0) ? 1 : 0);
	                    var Wil = Wil + Wi16l;
	                    var Wih = Wih + Wi16h + ((Wil >>> 0) < (Wi16l >>> 0) ? 1 : 0);

	                    Wi.high = Wih;
	                    Wi.low  = Wil;
	                }

	                var chh  = (eh & fh) ^ (~eh & gh);
	                var chl  = (el & fl) ^ (~el & gl);
	                var majh = (ah & bh) ^ (ah & ch) ^ (bh & ch);
	                var majl = (al & bl) ^ (al & cl) ^ (bl & cl);

	                var sigma0h = ((ah >>> 28) | (al << 4))  ^ ((ah << 30)  | (al >>> 2)) ^ ((ah << 25) | (al >>> 7));
	                var sigma0l = ((al >>> 28) | (ah << 4))  ^ ((al << 30)  | (ah >>> 2)) ^ ((al << 25) | (ah >>> 7));
	                var sigma1h = ((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((eh << 23) | (el >>> 9));
	                var sigma1l = ((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((el << 23) | (eh >>> 9));

	                // t1 = h + sigma1 + ch + K[i] + W[i]
	                var Ki  = K[i];
	                var Kih = Ki.high;
	                var Kil = Ki.low;

	                var t1l = hl + sigma1l;
	                var t1h = hh + sigma1h + ((t1l >>> 0) < (hl >>> 0) ? 1 : 0);
	                var t1l = t1l + chl;
	                var t1h = t1h + chh + ((t1l >>> 0) < (chl >>> 0) ? 1 : 0);
	                var t1l = t1l + Kil;
	                var t1h = t1h + Kih + ((t1l >>> 0) < (Kil >>> 0) ? 1 : 0);
	                var t1l = t1l + Wil;
	                var t1h = t1h + Wih + ((t1l >>> 0) < (Wil >>> 0) ? 1 : 0);

	                // t2 = sigma0 + maj
	                var t2l = sigma0l + majl;
	                var t2h = sigma0h + majh + ((t2l >>> 0) < (sigma0l >>> 0) ? 1 : 0);

	                // Update working variables
	                hh = gh;
	                hl = gl;
	                gh = fh;
	                gl = fl;
	                fh = eh;
	                fl = el;
	                el = (dl + t1l) | 0;
	                eh = (dh + t1h + ((el >>> 0) < (dl >>> 0) ? 1 : 0)) | 0;
	                dh = ch;
	                dl = cl;
	                ch = bh;
	                cl = bl;
	                bh = ah;
	                bl = al;
	                al = (t1l + t2l) | 0;
	                ah = (t1h + t2h + ((al >>> 0) < (t1l >>> 0) ? 1 : 0)) | 0;
	            }

	            // Intermediate hash value
	            H0l = H0.low  = (H0l + al);
	            H0.high = (H0h + ah + ((H0l >>> 0) < (al >>> 0) ? 1 : 0));
	            H1l = H1.low  = (H1l + bl);
	            H1.high = (H1h + bh + ((H1l >>> 0) < (bl >>> 0) ? 1 : 0));
	            H2l = H2.low  = (H2l + cl);
	            H2.high = (H2h + ch + ((H2l >>> 0) < (cl >>> 0) ? 1 : 0));
	            H3l = H3.low  = (H3l + dl);
	            H3.high = (H3h + dh + ((H3l >>> 0) < (dl >>> 0) ? 1 : 0));
	            H4l = H4.low  = (H4l + el);
	            H4.high = (H4h + eh + ((H4l >>> 0) < (el >>> 0) ? 1 : 0));
	            H5l = H5.low  = (H5l + fl);
	            H5.high = (H5h + fh + ((H5l >>> 0) < (fl >>> 0) ? 1 : 0));
	            H6l = H6.low  = (H6l + gl);
	            H6.high = (H6h + gh + ((H6l >>> 0) < (gl >>> 0) ? 1 : 0));
	            H7l = H7.low  = (H7l + hl);
	            H7.high = (H7h + hh + ((H7l >>> 0) < (hl >>> 0) ? 1 : 0));
	        },

	        _doFinalize: function () {
	            // Shortcuts
	            var data = this._data;
	            var dataWords = data.words;

	            var nBitsTotal = this._nDataBytes * 8;
	            var nBitsLeft = data.sigBytes * 8;

	            // Add padding
	            dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32);
	            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 30] = Math.floor(nBitsTotal / 0x100000000);
	            dataWords[(((nBitsLeft + 128) >>> 10) << 5) + 31] = nBitsTotal;
	            data.sigBytes = dataWords.length * 4;

	            // Hash final blocks
	            this._process();

	            // Convert hash to 32-bit word array before returning
	            var hash = this._hash.toX32();

	            // Return final computed hash
	            return hash;
	        },

	        clone: function () {
	            var clone = Hasher.clone.call(this);
	            clone._hash = this._hash.clone();

	            return clone;
	        },

	        blockSize: 1024/32
	    });

	    /**
	     * Shortcut function to the hasher's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     *
	     * @return {WordArray} The hash.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hash = CryptoJS.SHA512('message');
	     *     var hash = CryptoJS.SHA512(wordArray);
	     */
	    C.SHA512 = Hasher._createHelper(SHA512);

	    /**
	     * Shortcut function to the HMAC's object interface.
	     *
	     * @param {WordArray|string} message The message to hash.
	     * @param {WordArray|string} key The secret key.
	     *
	     * @return {WordArray} The HMAC.
	     *
	     * @static
	     *
	     * @example
	     *
	     *     var hmac = CryptoJS.HmacSHA512(message, key);
	     */
	    C.HmacSHA512 = Hasher._createHmacHelper(SHA512);
	}());


	return CryptoJS.SHA512;

}));

/***/ }),

/***/ "./node_modules/crypto-js/tripledes.js":
/*!*********************************************!*\
  !*** ./node_modules/crypto-js/tripledes.js ***!
  \*********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory, undef) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"), __webpack_require__(/*! ./enc-base64 */ "./node_modules/crypto-js/enc-base64.js"), __webpack_require__(/*! ./md5 */ "./node_modules/crypto-js/md5.js"), __webpack_require__(/*! ./evpkdf */ "./node_modules/crypto-js/evpkdf.js"), __webpack_require__(/*! ./cipher-core */ "./node_modules/crypto-js/cipher-core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function () {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var WordArray = C_lib.WordArray;
	    var BlockCipher = C_lib.BlockCipher;
	    var C_algo = C.algo;

	    // Permuted Choice 1 constants
	    var PC1 = [
	        57, 49, 41, 33, 25, 17, 9,  1,
	        58, 50, 42, 34, 26, 18, 10, 2,
	        59, 51, 43, 35, 27, 19, 11, 3,
	        60, 52, 44, 36, 63, 55, 47, 39,
	        31, 23, 15, 7,  62, 54, 46, 38,
	        30, 22, 14, 6,  61, 53, 45, 37,
	        29, 21, 13, 5,  28, 20, 12, 4
	    ];

	    // Permuted Choice 2 constants
	    var PC2 = [
	        14, 17, 11, 24, 1,  5,
	        3,  28, 15, 6,  21, 10,
	        23, 19, 12, 4,  26, 8,
	        16, 7,  27, 20, 13, 2,
	        41, 52, 31, 37, 47, 55,
	        30, 40, 51, 45, 33, 48,
	        44, 49, 39, 56, 34, 53,
	        46, 42, 50, 36, 29, 32
	    ];

	    // Cumulative bit shift constants
	    var BIT_SHIFTS = [1,  2,  4,  6,  8,  10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28];

	    // SBOXes and round permutation constants
	    var SBOX_P = [
	        {
	            0x0: 0x808200,
	            0x10000000: 0x8000,
	            0x20000000: 0x808002,
	            0x30000000: 0x2,
	            0x40000000: 0x200,
	            0x50000000: 0x808202,
	            0x60000000: 0x800202,
	            0x70000000: 0x800000,
	            0x80000000: 0x202,
	            0x90000000: 0x800200,
	            0xa0000000: 0x8200,
	            0xb0000000: 0x808000,
	            0xc0000000: 0x8002,
	            0xd0000000: 0x800002,
	            0xe0000000: 0x0,
	            0xf0000000: 0x8202,
	            0x8000000: 0x0,
	            0x18000000: 0x808202,
	            0x28000000: 0x8202,
	            0x38000000: 0x8000,
	            0x48000000: 0x808200,
	            0x58000000: 0x200,
	            0x68000000: 0x808002,
	            0x78000000: 0x2,
	            0x88000000: 0x800200,
	            0x98000000: 0x8200,
	            0xa8000000: 0x808000,
	            0xb8000000: 0x800202,
	            0xc8000000: 0x800002,
	            0xd8000000: 0x8002,
	            0xe8000000: 0x202,
	            0xf8000000: 0x800000,
	            0x1: 0x8000,
	            0x10000001: 0x2,
	            0x20000001: 0x808200,
	            0x30000001: 0x800000,
	            0x40000001: 0x808002,
	            0x50000001: 0x8200,
	            0x60000001: 0x200,
	            0x70000001: 0x800202,
	            0x80000001: 0x808202,
	            0x90000001: 0x808000,
	            0xa0000001: 0x800002,
	            0xb0000001: 0x8202,
	            0xc0000001: 0x202,
	            0xd0000001: 0x800200,
	            0xe0000001: 0x8002,
	            0xf0000001: 0x0,
	            0x8000001: 0x808202,
	            0x18000001: 0x808000,
	            0x28000001: 0x800000,
	            0x38000001: 0x200,
	            0x48000001: 0x8000,
	            0x58000001: 0x800002,
	            0x68000001: 0x2,
	            0x78000001: 0x8202,
	            0x88000001: 0x8002,
	            0x98000001: 0x800202,
	            0xa8000001: 0x202,
	            0xb8000001: 0x808200,
	            0xc8000001: 0x800200,
	            0xd8000001: 0x0,
	            0xe8000001: 0x8200,
	            0xf8000001: 0x808002
	        },
	        {
	            0x0: 0x40084010,
	            0x1000000: 0x4000,
	            0x2000000: 0x80000,
	            0x3000000: 0x40080010,
	            0x4000000: 0x40000010,
	            0x5000000: 0x40084000,
	            0x6000000: 0x40004000,
	            0x7000000: 0x10,
	            0x8000000: 0x84000,
	            0x9000000: 0x40004010,
	            0xa000000: 0x40000000,
	            0xb000000: 0x84010,
	            0xc000000: 0x80010,
	            0xd000000: 0x0,
	            0xe000000: 0x4010,
	            0xf000000: 0x40080000,
	            0x800000: 0x40004000,
	            0x1800000: 0x84010,
	            0x2800000: 0x10,
	            0x3800000: 0x40004010,
	            0x4800000: 0x40084010,
	            0x5800000: 0x40000000,
	            0x6800000: 0x80000,
	            0x7800000: 0x40080010,
	            0x8800000: 0x80010,
	            0x9800000: 0x0,
	            0xa800000: 0x4000,
	            0xb800000: 0x40080000,
	            0xc800000: 0x40000010,
	            0xd800000: 0x84000,
	            0xe800000: 0x40084000,
	            0xf800000: 0x4010,
	            0x10000000: 0x0,
	            0x11000000: 0x40080010,
	            0x12000000: 0x40004010,
	            0x13000000: 0x40084000,
	            0x14000000: 0x40080000,
	            0x15000000: 0x10,
	            0x16000000: 0x84010,
	            0x17000000: 0x4000,
	            0x18000000: 0x4010,
	            0x19000000: 0x80000,
	            0x1a000000: 0x80010,
	            0x1b000000: 0x40000010,
	            0x1c000000: 0x84000,
	            0x1d000000: 0x40004000,
	            0x1e000000: 0x40000000,
	            0x1f000000: 0x40084010,
	            0x10800000: 0x84010,
	            0x11800000: 0x80000,
	            0x12800000: 0x40080000,
	            0x13800000: 0x4000,
	            0x14800000: 0x40004000,
	            0x15800000: 0x40084010,
	            0x16800000: 0x10,
	            0x17800000: 0x40000000,
	            0x18800000: 0x40084000,
	            0x19800000: 0x40000010,
	            0x1a800000: 0x40004010,
	            0x1b800000: 0x80010,
	            0x1c800000: 0x0,
	            0x1d800000: 0x4010,
	            0x1e800000: 0x40080010,
	            0x1f800000: 0x84000
	        },
	        {
	            0x0: 0x104,
	            0x100000: 0x0,
	            0x200000: 0x4000100,
	            0x300000: 0x10104,
	            0x400000: 0x10004,
	            0x500000: 0x4000004,
	            0x600000: 0x4010104,
	            0x700000: 0x4010000,
	            0x800000: 0x4000000,
	            0x900000: 0x4010100,
	            0xa00000: 0x10100,
	            0xb00000: 0x4010004,
	            0xc00000: 0x4000104,
	            0xd00000: 0x10000,
	            0xe00000: 0x4,
	            0xf00000: 0x100,
	            0x80000: 0x4010100,
	            0x180000: 0x4010004,
	            0x280000: 0x0,
	            0x380000: 0x4000100,
	            0x480000: 0x4000004,
	            0x580000: 0x10000,
	            0x680000: 0x10004,
	            0x780000: 0x104,
	            0x880000: 0x4,
	            0x980000: 0x100,
	            0xa80000: 0x4010000,
	            0xb80000: 0x10104,
	            0xc80000: 0x10100,
	            0xd80000: 0x4000104,
	            0xe80000: 0x4010104,
	            0xf80000: 0x4000000,
	            0x1000000: 0x4010100,
	            0x1100000: 0x10004,
	            0x1200000: 0x10000,
	            0x1300000: 0x4000100,
	            0x1400000: 0x100,
	            0x1500000: 0x4010104,
	            0x1600000: 0x4000004,
	            0x1700000: 0x0,
	            0x1800000: 0x4000104,
	            0x1900000: 0x4000000,
	            0x1a00000: 0x4,
	            0x1b00000: 0x10100,
	            0x1c00000: 0x4010000,
	            0x1d00000: 0x104,
	            0x1e00000: 0x10104,
	            0x1f00000: 0x4010004,
	            0x1080000: 0x4000000,
	            0x1180000: 0x104,
	            0x1280000: 0x4010100,
	            0x1380000: 0x0,
	            0x1480000: 0x10004,
	            0x1580000: 0x4000100,
	            0x1680000: 0x100,
	            0x1780000: 0x4010004,
	            0x1880000: 0x10000,
	            0x1980000: 0x4010104,
	            0x1a80000: 0x10104,
	            0x1b80000: 0x4000004,
	            0x1c80000: 0x4000104,
	            0x1d80000: 0x4010000,
	            0x1e80000: 0x4,
	            0x1f80000: 0x10100
	        },
	        {
	            0x0: 0x80401000,
	            0x10000: 0x80001040,
	            0x20000: 0x401040,
	            0x30000: 0x80400000,
	            0x40000: 0x0,
	            0x50000: 0x401000,
	            0x60000: 0x80000040,
	            0x70000: 0x400040,
	            0x80000: 0x80000000,
	            0x90000: 0x400000,
	            0xa0000: 0x40,
	            0xb0000: 0x80001000,
	            0xc0000: 0x80400040,
	            0xd0000: 0x1040,
	            0xe0000: 0x1000,
	            0xf0000: 0x80401040,
	            0x8000: 0x80001040,
	            0x18000: 0x40,
	            0x28000: 0x80400040,
	            0x38000: 0x80001000,
	            0x48000: 0x401000,
	            0x58000: 0x80401040,
	            0x68000: 0x0,
	            0x78000: 0x80400000,
	            0x88000: 0x1000,
	            0x98000: 0x80401000,
	            0xa8000: 0x400000,
	            0xb8000: 0x1040,
	            0xc8000: 0x80000000,
	            0xd8000: 0x400040,
	            0xe8000: 0x401040,
	            0xf8000: 0x80000040,
	            0x100000: 0x400040,
	            0x110000: 0x401000,
	            0x120000: 0x80000040,
	            0x130000: 0x0,
	            0x140000: 0x1040,
	            0x150000: 0x80400040,
	            0x160000: 0x80401000,
	            0x170000: 0x80001040,
	            0x180000: 0x80401040,
	            0x190000: 0x80000000,
	            0x1a0000: 0x80400000,
	            0x1b0000: 0x401040,
	            0x1c0000: 0x80001000,
	            0x1d0000: 0x400000,
	            0x1e0000: 0x40,
	            0x1f0000: 0x1000,
	            0x108000: 0x80400000,
	            0x118000: 0x80401040,
	            0x128000: 0x0,
	            0x138000: 0x401000,
	            0x148000: 0x400040,
	            0x158000: 0x80000000,
	            0x168000: 0x80001040,
	            0x178000: 0x40,
	            0x188000: 0x80000040,
	            0x198000: 0x1000,
	            0x1a8000: 0x80001000,
	            0x1b8000: 0x80400040,
	            0x1c8000: 0x1040,
	            0x1d8000: 0x80401000,
	            0x1e8000: 0x400000,
	            0x1f8000: 0x401040
	        },
	        {
	            0x0: 0x80,
	            0x1000: 0x1040000,
	            0x2000: 0x40000,
	            0x3000: 0x20000000,
	            0x4000: 0x20040080,
	            0x5000: 0x1000080,
	            0x6000: 0x21000080,
	            0x7000: 0x40080,
	            0x8000: 0x1000000,
	            0x9000: 0x20040000,
	            0xa000: 0x20000080,
	            0xb000: 0x21040080,
	            0xc000: 0x21040000,
	            0xd000: 0x0,
	            0xe000: 0x1040080,
	            0xf000: 0x21000000,
	            0x800: 0x1040080,
	            0x1800: 0x21000080,
	            0x2800: 0x80,
	            0x3800: 0x1040000,
	            0x4800: 0x40000,
	            0x5800: 0x20040080,
	            0x6800: 0x21040000,
	            0x7800: 0x20000000,
	            0x8800: 0x20040000,
	            0x9800: 0x0,
	            0xa800: 0x21040080,
	            0xb800: 0x1000080,
	            0xc800: 0x20000080,
	            0xd800: 0x21000000,
	            0xe800: 0x1000000,
	            0xf800: 0x40080,
	            0x10000: 0x40000,
	            0x11000: 0x80,
	            0x12000: 0x20000000,
	            0x13000: 0x21000080,
	            0x14000: 0x1000080,
	            0x15000: 0x21040000,
	            0x16000: 0x20040080,
	            0x17000: 0x1000000,
	            0x18000: 0x21040080,
	            0x19000: 0x21000000,
	            0x1a000: 0x1040000,
	            0x1b000: 0x20040000,
	            0x1c000: 0x40080,
	            0x1d000: 0x20000080,
	            0x1e000: 0x0,
	            0x1f000: 0x1040080,
	            0x10800: 0x21000080,
	            0x11800: 0x1000000,
	            0x12800: 0x1040000,
	            0x13800: 0x20040080,
	            0x14800: 0x20000000,
	            0x15800: 0x1040080,
	            0x16800: 0x80,
	            0x17800: 0x21040000,
	            0x18800: 0x40080,
	            0x19800: 0x21040080,
	            0x1a800: 0x0,
	            0x1b800: 0x21000000,
	            0x1c800: 0x1000080,
	            0x1d800: 0x40000,
	            0x1e800: 0x20040000,
	            0x1f800: 0x20000080
	        },
	        {
	            0x0: 0x10000008,
	            0x100: 0x2000,
	            0x200: 0x10200000,
	            0x300: 0x10202008,
	            0x400: 0x10002000,
	            0x500: 0x200000,
	            0x600: 0x200008,
	            0x700: 0x10000000,
	            0x800: 0x0,
	            0x900: 0x10002008,
	            0xa00: 0x202000,
	            0xb00: 0x8,
	            0xc00: 0x10200008,
	            0xd00: 0x202008,
	            0xe00: 0x2008,
	            0xf00: 0x10202000,
	            0x80: 0x10200000,
	            0x180: 0x10202008,
	            0x280: 0x8,
	            0x380: 0x200000,
	            0x480: 0x202008,
	            0x580: 0x10000008,
	            0x680: 0x10002000,
	            0x780: 0x2008,
	            0x880: 0x200008,
	            0x980: 0x2000,
	            0xa80: 0x10002008,
	            0xb80: 0x10200008,
	            0xc80: 0x0,
	            0xd80: 0x10202000,
	            0xe80: 0x202000,
	            0xf80: 0x10000000,
	            0x1000: 0x10002000,
	            0x1100: 0x10200008,
	            0x1200: 0x10202008,
	            0x1300: 0x2008,
	            0x1400: 0x200000,
	            0x1500: 0x10000000,
	            0x1600: 0x10000008,
	            0x1700: 0x202000,
	            0x1800: 0x202008,
	            0x1900: 0x0,
	            0x1a00: 0x8,
	            0x1b00: 0x10200000,
	            0x1c00: 0x2000,
	            0x1d00: 0x10002008,
	            0x1e00: 0x10202000,
	            0x1f00: 0x200008,
	            0x1080: 0x8,
	            0x1180: 0x202000,
	            0x1280: 0x200000,
	            0x1380: 0x10000008,
	            0x1480: 0x10002000,
	            0x1580: 0x2008,
	            0x1680: 0x10202008,
	            0x1780: 0x10200000,
	            0x1880: 0x10202000,
	            0x1980: 0x10200008,
	            0x1a80: 0x2000,
	            0x1b80: 0x202008,
	            0x1c80: 0x200008,
	            0x1d80: 0x0,
	            0x1e80: 0x10000000,
	            0x1f80: 0x10002008
	        },
	        {
	            0x0: 0x100000,
	            0x10: 0x2000401,
	            0x20: 0x400,
	            0x30: 0x100401,
	            0x40: 0x2100401,
	            0x50: 0x0,
	            0x60: 0x1,
	            0x70: 0x2100001,
	            0x80: 0x2000400,
	            0x90: 0x100001,
	            0xa0: 0x2000001,
	            0xb0: 0x2100400,
	            0xc0: 0x2100000,
	            0xd0: 0x401,
	            0xe0: 0x100400,
	            0xf0: 0x2000000,
	            0x8: 0x2100001,
	            0x18: 0x0,
	            0x28: 0x2000401,
	            0x38: 0x2100400,
	            0x48: 0x100000,
	            0x58: 0x2000001,
	            0x68: 0x2000000,
	            0x78: 0x401,
	            0x88: 0x100401,
	            0x98: 0x2000400,
	            0xa8: 0x2100000,
	            0xb8: 0x100001,
	            0xc8: 0x400,
	            0xd8: 0x2100401,
	            0xe8: 0x1,
	            0xf8: 0x100400,
	            0x100: 0x2000000,
	            0x110: 0x100000,
	            0x120: 0x2000401,
	            0x130: 0x2100001,
	            0x140: 0x100001,
	            0x150: 0x2000400,
	            0x160: 0x2100400,
	            0x170: 0x100401,
	            0x180: 0x401,
	            0x190: 0x2100401,
	            0x1a0: 0x100400,
	            0x1b0: 0x1,
	            0x1c0: 0x0,
	            0x1d0: 0x2100000,
	            0x1e0: 0x2000001,
	            0x1f0: 0x400,
	            0x108: 0x100400,
	            0x118: 0x2000401,
	            0x128: 0x2100001,
	            0x138: 0x1,
	            0x148: 0x2000000,
	            0x158: 0x100000,
	            0x168: 0x401,
	            0x178: 0x2100400,
	            0x188: 0x2000001,
	            0x198: 0x2100000,
	            0x1a8: 0x0,
	            0x1b8: 0x2100401,
	            0x1c8: 0x100401,
	            0x1d8: 0x400,
	            0x1e8: 0x2000400,
	            0x1f8: 0x100001
	        },
	        {
	            0x0: 0x8000820,
	            0x1: 0x20000,
	            0x2: 0x8000000,
	            0x3: 0x20,
	            0x4: 0x20020,
	            0x5: 0x8020820,
	            0x6: 0x8020800,
	            0x7: 0x800,
	            0x8: 0x8020000,
	            0x9: 0x8000800,
	            0xa: 0x20800,
	            0xb: 0x8020020,
	            0xc: 0x820,
	            0xd: 0x0,
	            0xe: 0x8000020,
	            0xf: 0x20820,
	            0x80000000: 0x800,
	            0x80000001: 0x8020820,
	            0x80000002: 0x8000820,
	            0x80000003: 0x8000000,
	            0x80000004: 0x8020000,
	            0x80000005: 0x20800,
	            0x80000006: 0x20820,
	            0x80000007: 0x20,
	            0x80000008: 0x8000020,
	            0x80000009: 0x820,
	            0x8000000a: 0x20020,
	            0x8000000b: 0x8020800,
	            0x8000000c: 0x0,
	            0x8000000d: 0x8020020,
	            0x8000000e: 0x8000800,
	            0x8000000f: 0x20000,
	            0x10: 0x20820,
	            0x11: 0x8020800,
	            0x12: 0x20,
	            0x13: 0x800,
	            0x14: 0x8000800,
	            0x15: 0x8000020,
	            0x16: 0x8020020,
	            0x17: 0x20000,
	            0x18: 0x0,
	            0x19: 0x20020,
	            0x1a: 0x8020000,
	            0x1b: 0x8000820,
	            0x1c: 0x8020820,
	            0x1d: 0x20800,
	            0x1e: 0x820,
	            0x1f: 0x8000000,
	            0x80000010: 0x20000,
	            0x80000011: 0x800,
	            0x80000012: 0x8020020,
	            0x80000013: 0x20820,
	            0x80000014: 0x20,
	            0x80000015: 0x8020000,
	            0x80000016: 0x8000000,
	            0x80000017: 0x8000820,
	            0x80000018: 0x8020820,
	            0x80000019: 0x8000020,
	            0x8000001a: 0x8000800,
	            0x8000001b: 0x0,
	            0x8000001c: 0x20800,
	            0x8000001d: 0x820,
	            0x8000001e: 0x20020,
	            0x8000001f: 0x8020800
	        }
	    ];

	    // Masks that select the SBOX input
	    var SBOX_MASK = [
	        0xf8000001, 0x1f800000, 0x01f80000, 0x001f8000,
	        0x0001f800, 0x00001f80, 0x000001f8, 0x8000001f
	    ];

	    /**
	     * DES block cipher algorithm.
	     */
	    var DES = C_algo.DES = BlockCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;

	            // Select 56 bits according to PC1
	            var keyBits = [];
	            for (var i = 0; i < 56; i++) {
	                var keyBitPos = PC1[i] - 1;
	                keyBits[i] = (keyWords[keyBitPos >>> 5] >>> (31 - keyBitPos % 32)) & 1;
	            }

	            // Assemble 16 subkeys
	            var subKeys = this._subKeys = [];
	            for (var nSubKey = 0; nSubKey < 16; nSubKey++) {
	                // Create subkey
	                var subKey = subKeys[nSubKey] = [];

	                // Shortcut
	                var bitShift = BIT_SHIFTS[nSubKey];

	                // Select 48 bits according to PC2
	                for (var i = 0; i < 24; i++) {
	                    // Select from the left 28 key bits
	                    subKey[(i / 6) | 0] |= keyBits[((PC2[i] - 1) + bitShift) % 28] << (31 - i % 6);

	                    // Select from the right 28 key bits
	                    subKey[4 + ((i / 6) | 0)] |= keyBits[28 + (((PC2[i + 24] - 1) + bitShift) % 28)] << (31 - i % 6);
	                }

	                // Since each subkey is applied to an expanded 32-bit input,
	                // the subkey can be broken into 8 values scaled to 32-bits,
	                // which allows the key to be used without expansion
	                subKey[0] = (subKey[0] << 1) | (subKey[0] >>> 31);
	                for (var i = 1; i < 7; i++) {
	                    subKey[i] = subKey[i] >>> ((i - 1) * 4 + 3);
	                }
	                subKey[7] = (subKey[7] << 5) | (subKey[7] >>> 27);
	            }

	            // Compute inverse subkeys
	            var invSubKeys = this._invSubKeys = [];
	            for (var i = 0; i < 16; i++) {
	                invSubKeys[i] = subKeys[15 - i];
	            }
	        },

	        encryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._subKeys);
	        },

	        decryptBlock: function (M, offset) {
	            this._doCryptBlock(M, offset, this._invSubKeys);
	        },

	        _doCryptBlock: function (M, offset, subKeys) {
	            // Get input
	            this._lBlock = M[offset];
	            this._rBlock = M[offset + 1];

	            // Initial permutation
	            exchangeLR.call(this, 4,  0x0f0f0f0f);
	            exchangeLR.call(this, 16, 0x0000ffff);
	            exchangeRL.call(this, 2,  0x33333333);
	            exchangeRL.call(this, 8,  0x00ff00ff);
	            exchangeLR.call(this, 1,  0x55555555);

	            // Rounds
	            for (var round = 0; round < 16; round++) {
	                // Shortcuts
	                var subKey = subKeys[round];
	                var lBlock = this._lBlock;
	                var rBlock = this._rBlock;

	                // Feistel function
	                var f = 0;
	                for (var i = 0; i < 8; i++) {
	                    f |= SBOX_P[i][((rBlock ^ subKey[i]) & SBOX_MASK[i]) >>> 0];
	                }
	                this._lBlock = rBlock;
	                this._rBlock = lBlock ^ f;
	            }

	            // Undo swap from last round
	            var t = this._lBlock;
	            this._lBlock = this._rBlock;
	            this._rBlock = t;

	            // Final permutation
	            exchangeLR.call(this, 1,  0x55555555);
	            exchangeRL.call(this, 8,  0x00ff00ff);
	            exchangeRL.call(this, 2,  0x33333333);
	            exchangeLR.call(this, 16, 0x0000ffff);
	            exchangeLR.call(this, 4,  0x0f0f0f0f);

	            // Set output
	            M[offset] = this._lBlock;
	            M[offset + 1] = this._rBlock;
	        },

	        keySize: 64/32,

	        ivSize: 64/32,

	        blockSize: 64/32
	    });

	    // Swap bits across the left and right words
	    function exchangeLR(offset, mask) {
	        var t = ((this._lBlock >>> offset) ^ this._rBlock) & mask;
	        this._rBlock ^= t;
	        this._lBlock ^= t << offset;
	    }

	    function exchangeRL(offset, mask) {
	        var t = ((this._rBlock >>> offset) ^ this._lBlock) & mask;
	        this._lBlock ^= t;
	        this._rBlock ^= t << offset;
	    }

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.DES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.DES.decrypt(ciphertext, key, cfg);
	     */
	    C.DES = BlockCipher._createHelper(DES);

	    /**
	     * Triple-DES block cipher algorithm.
	     */
	    var TripleDES = C_algo.TripleDES = BlockCipher.extend({
	        _doReset: function () {
	            // Shortcuts
	            var key = this._key;
	            var keyWords = key.words;

	            // Create DES instances
	            this._des1 = DES.createEncryptor(WordArray.create(keyWords.slice(0, 2)));
	            this._des2 = DES.createEncryptor(WordArray.create(keyWords.slice(2, 4)));
	            this._des3 = DES.createEncryptor(WordArray.create(keyWords.slice(4, 6)));
	        },

	        encryptBlock: function (M, offset) {
	            this._des1.encryptBlock(M, offset);
	            this._des2.decryptBlock(M, offset);
	            this._des3.encryptBlock(M, offset);
	        },

	        decryptBlock: function (M, offset) {
	            this._des3.decryptBlock(M, offset);
	            this._des2.encryptBlock(M, offset);
	            this._des1.decryptBlock(M, offset);
	        },

	        keySize: 192/32,

	        ivSize: 64/32,

	        blockSize: 64/32
	    });

	    /**
	     * Shortcut functions to the cipher's object interface.
	     *
	     * @example
	     *
	     *     var ciphertext = CryptoJS.TripleDES.encrypt(message, key, cfg);
	     *     var plaintext  = CryptoJS.TripleDES.decrypt(ciphertext, key, cfg);
	     */
	    C.TripleDES = BlockCipher._createHelper(TripleDES);
	}());


	return CryptoJS.TripleDES;

}));

/***/ }),

/***/ "./node_modules/crypto-js/x64-core.js":
/*!********************************************!*\
  !*** ./node_modules/crypto-js/x64-core.js ***!
  \********************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

;(function (root, factory) {
	if (true) {
		// CommonJS
		module.exports = exports = factory(__webpack_require__(/*! ./core */ "./node_modules/crypto-js/core.js"));
	}
	else {}
}(this, function (CryptoJS) {

	(function (undefined) {
	    // Shortcuts
	    var C = CryptoJS;
	    var C_lib = C.lib;
	    var Base = C_lib.Base;
	    var X32WordArray = C_lib.WordArray;

	    /**
	     * x64 namespace.
	     */
	    var C_x64 = C.x64 = {};

	    /**
	     * A 64-bit word.
	     */
	    var X64Word = C_x64.Word = Base.extend({
	        /**
	         * Initializes a newly created 64-bit word.
	         *
	         * @param {number} high The high 32 bits.
	         * @param {number} low The low 32 bits.
	         *
	         * @example
	         *
	         *     var x64Word = CryptoJS.x64.Word.create(0x00010203, 0x04050607);
	         */
	        init: function (high, low) {
	            this.high = high;
	            this.low = low;
	        }

	        /**
	         * Bitwise NOTs this word.
	         *
	         * @return {X64Word} A new x64-Word object after negating.
	         *
	         * @example
	         *
	         *     var negated = x64Word.not();
	         */
	        // not: function () {
	            // var high = ~this.high;
	            // var low = ~this.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise ANDs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to AND with this word.
	         *
	         * @return {X64Word} A new x64-Word object after ANDing.
	         *
	         * @example
	         *
	         *     var anded = x64Word.and(anotherX64Word);
	         */
	        // and: function (word) {
	            // var high = this.high & word.high;
	            // var low = this.low & word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise ORs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to OR with this word.
	         *
	         * @return {X64Word} A new x64-Word object after ORing.
	         *
	         * @example
	         *
	         *     var ored = x64Word.or(anotherX64Word);
	         */
	        // or: function (word) {
	            // var high = this.high | word.high;
	            // var low = this.low | word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Bitwise XORs this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to XOR with this word.
	         *
	         * @return {X64Word} A new x64-Word object after XORing.
	         *
	         * @example
	         *
	         *     var xored = x64Word.xor(anotherX64Word);
	         */
	        // xor: function (word) {
	            // var high = this.high ^ word.high;
	            // var low = this.low ^ word.low;

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Shifts this word n bits to the left.
	         *
	         * @param {number} n The number of bits to shift.
	         *
	         * @return {X64Word} A new x64-Word object after shifting.
	         *
	         * @example
	         *
	         *     var shifted = x64Word.shiftL(25);
	         */
	        // shiftL: function (n) {
	            // if (n < 32) {
	                // var high = (this.high << n) | (this.low >>> (32 - n));
	                // var low = this.low << n;
	            // } else {
	                // var high = this.low << (n - 32);
	                // var low = 0;
	            // }

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Shifts this word n bits to the right.
	         *
	         * @param {number} n The number of bits to shift.
	         *
	         * @return {X64Word} A new x64-Word object after shifting.
	         *
	         * @example
	         *
	         *     var shifted = x64Word.shiftR(7);
	         */
	        // shiftR: function (n) {
	            // if (n < 32) {
	                // var low = (this.low >>> n) | (this.high << (32 - n));
	                // var high = this.high >>> n;
	            // } else {
	                // var low = this.high >>> (n - 32);
	                // var high = 0;
	            // }

	            // return X64Word.create(high, low);
	        // },

	        /**
	         * Rotates this word n bits to the left.
	         *
	         * @param {number} n The number of bits to rotate.
	         *
	         * @return {X64Word} A new x64-Word object after rotating.
	         *
	         * @example
	         *
	         *     var rotated = x64Word.rotL(25);
	         */
	        // rotL: function (n) {
	            // return this.shiftL(n).or(this.shiftR(64 - n));
	        // },

	        /**
	         * Rotates this word n bits to the right.
	         *
	         * @param {number} n The number of bits to rotate.
	         *
	         * @return {X64Word} A new x64-Word object after rotating.
	         *
	         * @example
	         *
	         *     var rotated = x64Word.rotR(7);
	         */
	        // rotR: function (n) {
	            // return this.shiftR(n).or(this.shiftL(64 - n));
	        // },

	        /**
	         * Adds this word with the passed word.
	         *
	         * @param {X64Word} word The x64-Word to add with this word.
	         *
	         * @return {X64Word} A new x64-Word object after adding.
	         *
	         * @example
	         *
	         *     var added = x64Word.add(anotherX64Word);
	         */
	        // add: function (word) {
	            // var low = (this.low + word.low) | 0;
	            // var carry = (low >>> 0) < (this.low >>> 0) ? 1 : 0;
	            // var high = (this.high + word.high + carry) | 0;

	            // return X64Word.create(high, low);
	        // }
	    });

	    /**
	     * An array of 64-bit words.
	     *
	     * @property {Array} words The array of CryptoJS.x64.Word objects.
	     * @property {number} sigBytes The number of significant bytes in this word array.
	     */
	    var X64WordArray = C_x64.WordArray = Base.extend({
	        /**
	         * Initializes a newly created word array.
	         *
	         * @param {Array} words (Optional) An array of CryptoJS.x64.Word objects.
	         * @param {number} sigBytes (Optional) The number of significant bytes in the words.
	         *
	         * @example
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create();
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create([
	         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
	         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
	         *     ]);
	         *
	         *     var wordArray = CryptoJS.x64.WordArray.create([
	         *         CryptoJS.x64.Word.create(0x00010203, 0x04050607),
	         *         CryptoJS.x64.Word.create(0x18191a1b, 0x1c1d1e1f)
	         *     ], 10);
	         */
	        init: function (words, sigBytes) {
	            words = this.words = words || [];

	            if (sigBytes != undefined) {
	                this.sigBytes = sigBytes;
	            } else {
	                this.sigBytes = words.length * 8;
	            }
	        },

	        /**
	         * Converts this 64-bit word array to a 32-bit word array.
	         *
	         * @return {CryptoJS.lib.WordArray} This word array's data as a 32-bit word array.
	         *
	         * @example
	         *
	         *     var x32WordArray = x64WordArray.toX32();
	         */
	        toX32: function () {
	            // Shortcuts
	            var x64Words = this.words;
	            var x64WordsLength = x64Words.length;

	            // Convert
	            var x32Words = [];
	            for (var i = 0; i < x64WordsLength; i++) {
	                var x64Word = x64Words[i];
	                x32Words.push(x64Word.high);
	                x32Words.push(x64Word.low);
	            }

	            return X32WordArray.create(x32Words, this.sigBytes);
	        },

	        /**
	         * Creates a copy of this word array.
	         *
	         * @return {X64WordArray} The clone.
	         *
	         * @example
	         *
	         *     var clone = x64WordArray.clone();
	         */
	        clone: function () {
	            var clone = Base.clone.call(this);

	            // Clone "words" array
	            var words = clone.words = this.words.slice(0);

	            // Clone each X64Word object
	            var wordsLength = words.length;
	            for (var i = 0; i < wordsLength; i++) {
	                words[i] = words[i].clone();
	            }

	            return clone;
	        }
	    });
	}());


	return CryptoJS;

}));

/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/crypto/bundle/bundle.js":
/*!*****************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/crypto/bundle/bundle.js ***!
  \*****************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var Curl = __webpack_require__(/*! ../curl/curl */ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js");
var Kerl = __webpack_require__(/*! ../kerl/kerl */ "./node_modules/iota.crypto.js/lib/crypto/kerl/kerl.js");
var Converter = __webpack_require__(/*! ../converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js");
var tritAdd = __webpack_require__(/*! ../helpers/adder */ "./node_modules/iota.crypto.js/lib/crypto/helpers/adder.js");

/**
*
*   @constructor bundle
**/
function Bundle() {

    // Declare empty bundle
    this.bundle = [];
}

/**
*
*
**/

Bundle.prototype.addEntry = function(signatureMessageLength, address, value, tag, timestamp, index) {

    for (var i = 0; i < signatureMessageLength; i++) {

        var transactionObject = new Object();
        transactionObject.address = address;
        transactionObject.value = i == 0 ? value : 0;
        transactionObject.obsoleteTag = tag;
        transactionObject.tag = tag;
        transactionObject.timestamp = timestamp;

        this.bundle[this.bundle.length] = transactionObject;
    }
}

/**
*
*
**/
Bundle.prototype.addTrytes = function(signatureFragments) {

    var emptySignatureFragment = '';
    var emptyHash = '999999999999999999999999999999999999999999999999999999999999999999999999999999999';
    var emptyTag = '9'.repeat(27);
    var emptyTimestamp = '9'.repeat(9);

    for (var j = 0; emptySignatureFragment.length < 2187; j++) {
        emptySignatureFragment += '9';
    }

    for (var i = 0; i < this.bundle.length; i++) {

        // Fill empty signatureMessageFragment
        this.bundle[i].signatureMessageFragment = signatureFragments[i] ? signatureFragments[i] : emptySignatureFragment;

        // Fill empty trunkTransaction
        this.bundle[i].trunkTransaction = emptyHash;

        // Fill empty branchTransaction
        this.bundle[i].branchTransaction = emptyHash;

        this.bundle[i].attachmentTimestamp = emptyTimestamp;
        this.bundle[i].attachmentTimestampLowerBound = emptyTimestamp;
        this.bundle[i].attachmentTimestampUpperBound = emptyTimestamp;
        // Fill empty nonce
        this.bundle[i].nonce = emptyTag;
    }
}


/**
*
*
**/
Bundle.prototype.finalize = function() {
    var validBundle = false;

  while(!validBundle) {

    var kerl = new Kerl();
    kerl.initialize();

    for (var i = 0; i < this.bundle.length; i++) {

        var valueTrits = Converter.trits(this.bundle[i].value);
        while (valueTrits.length < 81) {
            valueTrits[valueTrits.length] = 0;
        }

        var timestampTrits = Converter.trits(this.bundle[i].timestamp);
        while (timestampTrits.length < 27) {
            timestampTrits[timestampTrits.length] = 0;
        }

        var currentIndexTrits = Converter.trits(this.bundle[i].currentIndex = i);
        while (currentIndexTrits.length < 27) {
            currentIndexTrits[currentIndexTrits.length] = 0;
        }

        var lastIndexTrits = Converter.trits(this.bundle[i].lastIndex = this.bundle.length - 1);
        while (lastIndexTrits.length < 27) {
            lastIndexTrits[lastIndexTrits.length] = 0;
        }

        var bundleEssence = Converter.trits(this.bundle[i].address + Converter.trytes(valueTrits) + this.bundle[i].obsoleteTag + Converter.trytes(timestampTrits) + Converter.trytes(currentIndexTrits) + Converter.trytes(lastIndexTrits));
        kerl.absorb(bundleEssence, 0, bundleEssence.length);
    }

    var hash = [];
    kerl.squeeze(hash, 0, Curl.HASH_LENGTH);
    hash = Converter.trytes(hash);

    for (var i = 0; i < this.bundle.length; i++) {

        this.bundle[i].bundle = hash;
    }

    var normalizedHash = this.normalizedBundle(hash);
    if(normalizedHash.indexOf(13 /* = M */) != -1) {
      // Insecure bundle. Increment Tag and recompute bundle hash.
      var increasedTag = tritAdd(Converter.trits(this.bundle[0].obsoleteTag), [1]);
      this.bundle[0].obsoleteTag = Converter.trytes(increasedTag);
    } else {
      validBundle = true;
    }
  }
}

/**
*   Normalizes the bundle hash
*
**/
Bundle.prototype.normalizedBundle = function(bundleHash) {

    var normalizedBundle = [];

    for (var i = 0; i < 3; i++) {

        var sum = 0;
        for (var j = 0; j < 27; j++) {

            sum += (normalizedBundle[i * 27 + j] = Converter.value(Converter.trits(bundleHash.charAt(i * 27 + j))));
        }

        if (sum >= 0) {

            while (sum-- > 0) {

                for (var j = 0; j < 27; j++) {

                    if (normalizedBundle[i * 27 + j] > -13) {

                        normalizedBundle[i * 27 + j]--;
                        break;
                    }
                }
            }
        } else {

            while (sum++ < 0) {

                for (var j = 0; j < 27; j++) {

                    if (normalizedBundle[i * 27 + j] < 13) {

                        normalizedBundle[i * 27 + j]++;
                        break;
                    }
                }
            }
        }
    }

    return normalizedBundle;
}

module.exports = Bundle;


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js":
/*!***********************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/crypto/converter/converter.js ***!
  \***********************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

/**
 *
 *   Conversion functions
 *
 **/

var RADIX = 3;
var RADIX_BYTES = 256;
var MAX_TRIT_VALUE = 1;
var MIN_TRIT_VALUE = -1;
var BYTE_HASH_LENGTH = 48;

// All possible tryte values
var trytesAlphabet = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ"

// map of all trits representations
var trytesTrits = [
    [ 0,  0,  0],
    [ 1,  0,  0],
    [-1,  1,  0],
    [ 0,  1,  0],
    [ 1,  1,  0],
    [-1, -1,  1],
    [ 0, -1,  1],
    [ 1, -1,  1],
    [-1,  0,  1],
    [ 0,  0,  1],
    [ 1,  0,  1],
    [-1,  1,  1],
    [ 0,  1,  1],
    [ 1,  1,  1],
    [-1, -1, -1],
    [ 0, -1, -1],
    [ 1, -1, -1],
    [-1,  0, -1],
    [ 0,  0, -1],
    [ 1,  0, -1],
    [-1,  1, -1],
    [ 0,  1, -1],
    [ 1,  1, -1],
    [-1, -1,  0],
    [ 0, -1,  0],
    [ 1, -1,  0],
    [-1,  0,  0]
];

/**
 *   Converts trytes into trits
 *
 *   @method trits
 *   @param {String|Int} input Tryte value to be converted. Can either be string or int
 *   @param {Array} state (optional) state to be modified
 *   @returns {Array} trits
 **/
var trits = function( input, state ) {

    var trits = state || [];

    if (Number.isInteger(input)) {

        var absoluteValue = input < 0 ? -input : input;

        while (absoluteValue > 0) {

            var remainder = absoluteValue % 3;
            absoluteValue = Math.floor(absoluteValue / 3);

            if (remainder > 1) {
                remainder = -1;
                absoluteValue++;
            }

            trits[trits.length] = remainder;
        }
        if (input < 0) {

            for (var i = 0; i < trits.length; i++) {

                trits[i] = -trits[i];
            }
        }
    } else {

        for (var i = 0; i < input.length; i++) {

            var index = trytesAlphabet.indexOf(input.charAt(i));
            trits[i * 3] = trytesTrits[index][0];
            trits[i * 3 + 1] = trytesTrits[index][1];
            trits[i * 3 + 2] = trytesTrits[index][2];
        }
    }

    return trits;
}

/**
 *   Converts trits into trytes
 *
 *   @method trytes
 *   @param {Array} trits
 *   @returns {String} trytes
 **/
var trytes = function(trits) {

    var trytes = "";

    for ( var i = 0; i < trits.length; i += 3 ) {

        // Iterate over all possible tryte values to find correct trit representation
        for ( var j = 0; j < trytesAlphabet.length; j++ ) {

            if ( trytesTrits[ j ][ 0 ] === trits[ i ] && trytesTrits[ j ][ 1 ] === trits[ i + 1 ] && trytesTrits[ j ][ 2 ] === trits[ i + 2 ] ) {

                trytes += trytesAlphabet.charAt( j );
                break;

            }

        }

    }

    return trytes;
}

/**
 *   Converts trits into an integer value
 *
 *   @method value
 *   @param {Array} trits
 *   @returns {int} value
 **/
var value = function(trits) {

    var returnValue = 0;

    for ( var i = trits.length; i-- > 0; ) {

        returnValue = returnValue * 3 + trits[ i ];
    }

    return returnValue;
}

/**
 *   Converts an integer value to trits
 *
 *   @method value
 *   @param {Int} value
 *   @returns {Array} trits
 **/
var fromValue = function(value) {

    var destination = [];
    var absoluteValue = value < 0 ? -value : value;
    var i = 0;

    while( absoluteValue > 0 ) {

        var remainder = ( absoluteValue % RADIX );
        absoluteValue = Math.floor( absoluteValue / RADIX );

        if ( remainder > MAX_TRIT_VALUE ) {

            remainder = MIN_TRIT_VALUE;
            absoluteValue++;

        }

        destination[ i ] = remainder;
        i++;

    }

    if ( value < 0 ) {

        for ( var j = 0; j < destination.length; j++ ) {

            // switch values
            destination[ j ] = destination[ j ] === 0 ? 0: -destination[ j ];

        }

    }

    return destination;
}

module.exports = {
    trits           : trits,
    trytes          : trytes,
    value           : value,
    fromValue       : fromValue
};


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/crypto/converter/words.js":
/*!*******************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/crypto/converter/words.js ***!
  \*******************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

var INT_LENGTH = 12;
var BYTE_LENGTH = 48;
var RADIX = 3;
/// hex representation of (3^242)/2
var HALF_3 = new Uint32Array([
    0xa5ce8964,
    0x9f007669,
    0x1484504f,
    0x3ade00d9,
    0x0c24486e,
    0x50979d57,
    0x79a4c702,
    0x48bbae36,
    0xa9f6808b,
    0xaa06a805,
    0xa87fabdf,
    0x5e69ebef
]);

var clone_uint32Array = function(sourceArray) {
  var destination = new ArrayBuffer(sourceArray.byteLength);
  new Uint32Array(destination).set(new Uint32Array(sourceArray));

  return destination;
};

var ta_slice = function(array) {
  if (array.slice !== undefined) {
      return array.slice();
  }

  return clone_uint32Array(array);
};

var ta_reverse = function(array) {
  if (array.reverse !== undefined) {
    array.reverse();
    return;
  }

  var i = 0,
    n = array.length,
    middle = Math.floor(n / 2),
    temp = null;

  for (; i < middle; i += 1) {
    temp = array[i];
    array[i] = array[n - 1 - i];
    array[n - 1 - i] = temp;
  }
};

/// negates the (unsigned) input array
var bigint_not = function(arr) {
    for (var i = 0; i < arr.length; i++) {
        arr[i] = (~arr[i]) >>> 0;
    }
};

/// rshift that works with up to 53
/// JS's shift operators only work on 32 bit integers
/// ours is up to 33 or 34 bits though, so
/// we need to implement shifting manually
var rshift = function(number, shift) {
    return (number / Math.pow(2, shift)) >>> 0;
};

/// swaps endianness
var swap32 = function(val) {
    return ((val & 0xFF) << 24) |
        ((val & 0xFF00) << 8) |
        ((val >> 8) & 0xFF00) |
        ((val >> 24) & 0xFF);
}

/// add with carry
var full_add = function(lh, rh, carry) {
    var v = lh + rh;
    var l = (rshift(v, 32)) & 0xFFFFFFFF;
    var r = (v & 0xFFFFFFFF) >>> 0;
    var carry1 = l != 0;

    if (carry) {
        v = r + 1;
    }
    l = (rshift(v, 32)) & 0xFFFFFFFF;
    r = (v & 0xFFFFFFFF) >>> 0;
    var carry2 = l != 0;

    return [r, carry1 || carry2];
};

/// subtracts rh from base
var bigint_sub = function(base, rh) {
    var noborrow = true;

    for (var i = 0; i < base.length; i++) {
        var vc = full_add(base[i], (~rh[i] >>> 0), noborrow);
        base[i] = vc[0];
        noborrow = vc[1];
    }

    if (!noborrow) {
        throw "noborrow";
    }
};

/// compares two (unsigned) big integers
var bigint_cmp = function(lh, rh) {
    for (var i = lh.length; i-- > 0;) {
        var a = lh[i] >>> 0;
        var b = rh[i] >>> 0;
        if (a < b) {
            return -1;
        } else if (a > b) {
            return 1;
        }
    }
    return 0;
};

/// adds rh to base in place
var bigint_add = function(base, rh) {
    var carry = false;
    for (var i = 0; i < base.length; i++) {
        var vc = full_add(base[i], rh[i], carry);
        base[i] = vc[0];
        carry = vc[1];
    }
};

/// adds a small (i.e. <32bit) number to base
var bigint_add_small = function(base, other) {
    var vc = full_add(base[0], other, false);
    base[0] = vc[0];
    var carry = vc[1];

    var i = 1;
    while (carry && i < base.length) {
        var vc = full_add(base[i], 0, carry);
        base[i] = vc[0];
        carry = vc[1];
        i += 1;
    }

    return i;
};

/// converts the given byte array to trits
var words_to_trits = function(words) {
    if (words.length != INT_LENGTH) {
        throw "Invalid words length";
    }

    var trits = new Int8Array(243);
    var base = new Uint32Array(words);

    ta_reverse(base);

    var flip_trits = false;
    if (base[INT_LENGTH - 1] >> 31 == 0) {
        // positive two's complement number.
        // add HALF_3 to move it to the right place.
        bigint_add(base, HALF_3);
    } else {
        // negative number.
        bigint_not(base);
        if (bigint_cmp(base, HALF_3) > 0) {
            bigint_sub(base, HALF_3);
            flip_trits = true;
        } else {
            /// bigint is between (unsigned) HALF_3 and (2**384 - 3**242/2).
            bigint_add_small(base, 1);
            var tmp = ta_slice(HALF_3);
            bigint_sub(tmp, base);
            base = tmp;
        }
    }


    var rem = 0;

    for (var i = 0; i < 242; i++) {
        rem = 0;
        for (var j = INT_LENGTH - 1; j >= 0; j--) {
            var lhs = (rem != 0 ? rem * 0xFFFFFFFF + rem : 0) + base[j];
            var rhs = RADIX;

            var q = (lhs / rhs) >>> 0;
            var r = (lhs % rhs) >>> 0;

            base[j] = q;
            rem = r;
        }

        trits[i] = rem - 1;
    }

    if (flip_trits) {
        for (var i = 0; i < trits.length; i++) {
            trits[i] = -trits[i];
        }
    }

    return trits;
}

var is_null = function(arr) {
    for (var i = 0; i < arr.length; i++) {
        if (arr[i] != 0) {
            return false;
            break;
        }
    }
    return true;
}

var trits_to_words = function(trits) {
    if (trits.length != 243) {
        throw "Invalid trits length";
    }

    var base = new Uint32Array(INT_LENGTH);

    if (trits.slice(0, 242).every(function(a) {
            a == -1
        })) {
        base = ta_slice(HALF_3);
        bigint_not(base);
        bigint_add_small(base, 1);
    } else {
        var size = 1;
        for (var i = trits.length - 1; i-- > 0;) {
            var trit = trits[i] + 1;

            //multiply by radix
            {
                var sz = size;
                var carry = 0;

                for (var j = 0; j < sz; j++) {
                    var v = base[j] * RADIX + carry;
                    carry = rshift(v, 32);
                    base[j] = (v & 0xFFFFFFFF) >>> 0;
                }

                if (carry > 0) {
                    base[sz] = carry;
                    size += 1;
                }
            }

            //addition
            {
                var sz = bigint_add_small(base, trit);
                if (sz > size) {
                    size = sz;
                }
            }
        }

        if (!is_null(base)) {
            if (bigint_cmp(HALF_3, base) <= 0) {
                // base >= HALF_3
                // just do base - HALF_3
                bigint_sub(base, HALF_3);
            } else {
                // base < HALF_3
                // so we need to transform it to a two's complement representation
                // of (base - HALF_3).
                // as we don't have a wrapping (-), we need to use some bit magic
                var tmp = ta_slice(HALF_3);
                bigint_sub(tmp, base);
                bigint_not(tmp);
                bigint_add_small(tmp, 1);
                base = tmp;
            }
        }
    }

    ta_reverse(base);

    for (var i = 0; i < base.length; i++) {
        base[i] = swap32(base[i]);
    }

    return base;
};

module.exports = {
    trits_to_words: trits_to_words,
    words_to_trits: words_to_trits
};


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js":
/*!*************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/crypto/curl/curl.js ***!
  \*************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var Converter = __webpack_require__(/*! ../converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js");

/**
**      Cryptographic related functions to IOTA's Curl (sponge function)
**/

var NUMBER_OF_ROUNDS = 81;
var HASH_LENGTH = 243;
var STATE_LENGTH = 3 * HASH_LENGTH;

function Curl(rounds) {
    if (rounds) {
      this.rounds = rounds;
    } else {
      this.rounds = NUMBER_OF_ROUNDS;
    }
    // truth table
    this.truthTable = [1, 0, -1, 2, 1, -1, 0, 2, -1, 1, 0];
}

Curl.HASH_LENGTH = HASH_LENGTH;

/**
*   Initializes the state with STATE_LENGTH trits
*
*   @method initialize
**/
Curl.prototype.initialize = function(state, length) {

    if (state) {

        this.state = state;

    } else {

        this.state = [];

        for (var i = 0; i < STATE_LENGTH; i++) {

            this.state[i] = 0;

        }
    }
}

Curl.prototype.reset = function() {
  this.initialize();
}

/**
*   Sponge absorb function
*
*   @method absorb
**/
Curl.prototype.absorb = function(trits, offset, length) {

    do {

        var i = 0;
        var limit = (length < HASH_LENGTH ? length : HASH_LENGTH);

        while (i < limit) {

            this.state[i++] = trits[offset++];
        }

        this.transform();

    } while (( length -= HASH_LENGTH ) > 0)

}

/**
*   Sponge squeeze function
*
*   @method squeeze
**/
Curl.prototype.squeeze = function(trits, offset, length) {

    do {

        var i = 0;
        var limit = (length < HASH_LENGTH ? length : HASH_LENGTH);

        while (i < limit) {

            trits[offset++] = this.state[i++];
        }

        this.transform();

    } while (( length -= HASH_LENGTH ) > 0)
}

/**
*   Sponge transform function
*
*   @method transform
**/
Curl.prototype.transform = function() {

    var stateCopy = [], index = 0;

    for (var round = 0; round < this.rounds; round++) {

        stateCopy = this.state.slice();

        for (var i = 0; i < STATE_LENGTH; i++) {

            this.state[i] = this.truthTable[stateCopy[index] + (stateCopy[index += (index < 365 ? 364 : -365)] << 2) + 5];
        }
    }
}

module.exports = Curl


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/crypto/helpers/adder.js":
/*!*****************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/crypto/helpers/adder.js ***!
  \*****************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

/* copyright Paul Handy, 2017 */

function sum( a, b ) {

    var s = a + b;

    switch( s ) {

        case 2: return -1;
        case -2: return 1;
        default: return s;

    }
}

function cons( a, b ) {

    if( a === b ) {

        return a;

    }

    return 0;
}

function any( a, b ) {

    var s = a + b;

    if ( s > 0 ) {

        return 1;

    } else if ( s < 0 ) {

        return -1;

    }

    return 0;
}

function full_add( a, b, c ) {

    var s_a     =   sum( a, b );
    var c_a     =   cons( a, b );
    var c_b     =   cons( s_a, c );
    var c_out   =   any( c_a, c_b );
    var s_out   =   sum( s_a, c );

    return [ s_out, c_out ];

}

function add( a, b ) {

    var out = new Array( Math.max( a.length, b.length ) );
    var carry = 0;
    var a_i, b_i;

    for( var i = 0; i < out.length; i++ ) {

        a_i = i < a.length ? a[ i ] : 0;
        b_i = i < b.length ? b[ i ] : 0;
        var f_a = full_add( a_i, b_i, carry );
        out[ i ] = f_a[ 0 ];
        carry = f_a[ 1 ];

    }

    return out;

}

module.exports = add;


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/crypto/hmac/hmac.js":
/*!*************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/crypto/hmac/hmac.js ***!
  \*************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var Curl = __webpack_require__(/*! ../curl/curl */ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js");
var Converter = __webpack_require__(/*! ../converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js");
var HMAC_ROUNDS = 27;

function hmac(key) {
    this._key = Converter.trits(key);
}

hmac.prototype.addHMAC = function(bundle) {
    var curl = new Curl(HMAC_ROUNDS);
    var key = this._key;
    for(var i = 0; i < bundle.bundle.length; i++) {
        if (bundle.bundle[i].value > 0) {
            var bundleHashTrits = Converter.trits(bundle.bundle[i].bundle);
            var hmac = new Int8Array(243);
            curl.initialize();
            curl.absorb(key);
            curl.absorb(bundleHashTrits);
            curl.squeeze(hmac);
            var hmacTrytes = Converter.trytes(hmac);
            bundle.bundle[i].signatureMessageFragment = hmacTrytes + bundle.bundle[i].signatureMessageFragment.substring(81, 2187);
        }
    }
}

module.exports = hmac;


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/crypto/kerl/kerl.js":
/*!*************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/crypto/kerl/kerl.js ***!
  \*************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var CryptoJS = __webpack_require__(/*! crypto-js */ "./node_modules/crypto-js/index.js");
var Converter = __webpack_require__(/*! ../converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js");
var Curl = __webpack_require__(/*! ../curl/curl */ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js");
var WConverter = __webpack_require__(/*! ../converter/words */ "./node_modules/iota.crypto.js/lib/crypto/converter/words.js");

var BIT_HASH_LENGTH = 384;

function Kerl() {


    this.k = CryptoJS.algo.SHA3.create();
    this.k.init({
        outputLength: BIT_HASH_LENGTH
    });
}

Kerl.BIT_HASH_LENGTH = BIT_HASH_LENGTH;
Kerl.HASH_LENGTH = Curl.HASH_LENGTH;

Kerl.prototype.initialize = function(state) {}

Kerl.prototype.reset = function() {

    this.k.reset();

}

Kerl.prototype.absorb = function(trits, offset, length) {


    if (length && ((length % 243) !== 0)) {

        throw new Error('Illegal length provided');

    }

    do {
        var limit = (length < Curl.HASH_LENGTH ? length : Curl.HASH_LENGTH);

        var trit_state = trits.slice(offset, offset + limit);
        offset += limit;

        // convert trit state to words
        var wordsToAbsorb = WConverter.trits_to_words(trit_state);

        // absorb the trit stat as wordarray
        this.k.update(
            CryptoJS.lib.WordArray.create(wordsToAbsorb));

    } while ((length -= Curl.HASH_LENGTH) > 0);

}



Kerl.prototype.squeeze = function(trits, offset, length) {

    if (length && ((length % 243) !== 0)) {

        throw new Error('Illegal length provided');

    }
    do {

        // get the hash digest
        var kCopy = this.k.clone();
        var final = kCopy.finalize();

        // Convert words to trits and then map it into the internal state
        var trit_state = WConverter.words_to_trits(final.words);

        var i = 0;
        var limit = (length < Curl.HASH_LENGTH ? length : Curl.HASH_LENGTH);

        while (i < limit) {
            trits[offset++] = trit_state[i++];
        }

        this.reset();

        for (i = 0; i < final.words.length; i++) {
            final.words[i] = final.words[i] ^ 0xFFFFFFFF;
        }

        this.k.update(final);

    } while ((length -= Curl.HASH_LENGTH) > 0);
}

module.exports = Kerl;


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/crypto/signing/oldSigning.js":
/*!**********************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/crypto/signing/oldSigning.js ***!
  \**********************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var Curl = __webpack_require__(/*! ../curl/curl */ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js");
var Converter = __webpack_require__(/*! ../converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js");
var Bundle = __webpack_require__(/*! ../bundle/bundle */ "./node_modules/iota.crypto.js/lib/crypto/bundle/bundle.js");
var add = __webpack_require__(/*! ../helpers/adder */ "./node_modules/iota.crypto.js/lib/crypto/helpers/adder.js");

/**
*           Signing related functions
*
**/
var key = function(seed, index, length) {

    while ((seed.length % 243) !== 0) {
      seed.push(0);
    }

    var indexTrits = Converter.fromValue( index );
    var subseed = add( seed.slice( ), indexTrits );

    var curl = new Curl( );

    curl.initialize( );
    curl.absorb(subseed, 0, subseed.length);
    curl.squeeze(subseed, 0, subseed.length);

    curl.initialize( );
    curl.absorb(subseed, 0, subseed.length);

    var key = [], offset = 0, buffer = [];

    while (length-- > 0) {

        for (var i = 0; i < 27; i++) {

            curl.squeeze(buffer, 0, subseed.length);
            for (var j = 0; j < 243; j++) {

                key[offset++] = buffer[j];
            }
        }
    }
    return key;
}

/**
*
*
**/
var digests = function(key) {

    var digests = [], buffer = [];

    for (var i = 0; i < Math.floor(key.length / 6561); i++) {

        var keyFragment = key.slice(i * 6561, (i + 1) * 6561);

        for (var j = 0; j < 27; j++) {

            buffer = keyFragment.slice(j * 243, (j + 1) * 243);

            for (var k = 0; k < 26; k++) {

                var kCurl = new Curl();
                kCurl.initialize();
                kCurl.absorb(buffer, 0, buffer.length);
                kCurl.squeeze(buffer, 0, Curl.HASH_LENGTH);
            }

            for (var k = 0; k < 243; k++) {

                keyFragment[j * 243 + k] = buffer[k];
            }
        }

        var curl = new Curl()

        curl.initialize();
        curl.absorb(keyFragment, 0, keyFragment.length);
        curl.squeeze(buffer, 0, Curl.HASH_LENGTH);

        for (var j = 0; j < 243; j++) {

            digests[i * 243 + j] = buffer[j];
        }
    }
    return digests;
}

/**
*
*
**/
var address = function(digests) {

    var addressTrits = [];

    var curl = new Curl();

    curl.initialize();
    curl.absorb(digests, 0, digests.length);
    curl.squeeze(addressTrits, 0, Curl.HASH_LENGTH);

    return addressTrits;
}

/**
*
*
**/
var digest = function(normalizedBundleFragment, signatureFragment) {

    var buffer = []

    var curl = new Curl();

    curl.initialize();

    for (var i = 0; i< 27; i++) {
        buffer = signatureFragment.slice(i * 243, (i + 1) * 243);

        for (var j = normalizedBundleFragment[i] + 13; j-- > 0; ) {

            var jCurl = new Curl();

            jCurl.initialize();
            jCurl.absorb(buffer, 0, buffer.length);
            jCurl.squeeze(buffer, 0, Curl.HASH_LENGTH);
        }

        curl.absorb(buffer, 0, buffer.length);
    }

    curl.squeeze(buffer, 0, Curl.HASH_LENGTH);
    return buffer;
}

/**
*
*
**/
var signatureFragment = function(normalizedBundleFragment, keyFragment) {

    var signatureFragment = keyFragment.slice(), hash = [];

    var curl = new Curl();

    for (var i = 0; i < 27; i++) {

        hash = signatureFragment.slice(i * 243, (i + 1) * 243);

        for (var j = 0; j < 13 - normalizedBundleFragment[i]; j++) {

            curl.initialize();
            curl.absorb(hash, 0, hash.length);
            curl.squeeze(hash, 0, Curl.HASH_LENGTH);
        }

        for (var j = 0; j < 243; j++) {

            signatureFragment[i * 243 + j] = hash[j];
        }
    }

    return signatureFragment;
}

/**
*
*
**/
var validateSignatures = function(expectedAddress, signatureFragments, bundleHash) {

    var self = this;
    var bundle = new Bundle();

    var normalizedBundleFragments = [];
    var normalizedBundleHash = bundle.normalizedBundle(bundleHash);

    // Split hash into 3 fragments
    for (var i = 0; i < 3; i++) {
        normalizedBundleFragments[i] = normalizedBundleHash.slice(i * 27, (i + 1) * 27);
    }

    // Get digests
    var digests = [];

    for (var i = 0; i < signatureFragments.length; i++) {

        var digestBuffer = digest(normalizedBundleFragments[i % 3], Converter.trits(signatureFragments[i]));

        for (var j = 0; j < 243; j++) {

            digests[i * 243 + j] = digestBuffer[j]
        }
    }

    var address = Converter.trytes(self.address(digests));

    return (expectedAddress === address);
}


module.exports = {
    key                 : key,
    digests             : digests,
    address             : address,
    digest              : digest,
    signatureFragment   : signatureFragment,
    validateSignatures  : validateSignatures
}


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/crypto/signing/signing.js":
/*!*******************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/crypto/signing/signing.js ***!
  \*******************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var Curl = __webpack_require__(/*! ../curl/curl */ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js");
var Kerl = __webpack_require__(/*! ../kerl/kerl */ "./node_modules/iota.crypto.js/lib/crypto/kerl/kerl.js");
var Converter = __webpack_require__(/*! ../converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js");
var Bundle = __webpack_require__(/*! ../bundle/bundle */ "./node_modules/iota.crypto.js/lib/crypto/bundle/bundle.js");
var add = __webpack_require__(/*! ../helpers/adder */ "./node_modules/iota.crypto.js/lib/crypto/helpers/adder.js");
var oldSigning = __webpack_require__(/*! ./oldSigning */ "./node_modules/iota.crypto.js/lib/crypto/signing/oldSigning.js");
var errors = __webpack_require__(/*! ../../errors/inputErrors */ "./node_modules/iota.crypto.js/lib/errors/inputErrors.js");

/**
*           Signing related functions
*
**/
var key = function(seed, index, length) {

    while ((seed.length % 243) !== 0) {
      seed.push(0);
    }

    var indexTrits = Converter.fromValue( index );
    var subseed = add( seed.slice( ), indexTrits );

    var kerl = new Kerl( );

    kerl.initialize( );
    kerl.absorb(subseed, 0, subseed.length);
    kerl.squeeze(subseed, 0, subseed.length);

    kerl.reset( );
    kerl.absorb(subseed, 0, subseed.length);

    var key = [], offset = 0, buffer = [];

    while (length-- > 0) {

        for (var i = 0; i < 27; i++) {

            kerl.squeeze(buffer, 0, subseed.length);
            for (var j = 0; j < 243; j++) {

                key[offset++] = buffer[j];
            }
        }
    }
    return key;
}

/**
*
*
**/
var digests = function(key) {

    var digests = [], buffer = [];

    for (var i = 0; i < Math.floor(key.length / 6561); i++) {

        var keyFragment = key.slice(i * 6561, (i + 1) * 6561);

        for (var j = 0; j < 27; j++) {

            buffer = keyFragment.slice(j * 243, (j + 1) * 243);

            for (var k = 0; k < 26; k++) {

                var kKerl = new Kerl();
                kKerl.initialize();
                kKerl.absorb(buffer, 0, buffer.length);
                kKerl.squeeze(buffer, 0, Curl.HASH_LENGTH);
            }

            for (var k = 0; k < 243; k++) {

                keyFragment[j * 243 + k] = buffer[k];
            }
        }

        var kerl = new Kerl()

        kerl.initialize();
        kerl.absorb(keyFragment, 0, keyFragment.length);
        kerl.squeeze(buffer, 0, Curl.HASH_LENGTH);

        for (var j = 0; j < 243; j++) {

            digests[i * 243 + j] = buffer[j];
        }
    }
    return digests;
}

/**
*
*
**/
var address = function(digests) {

    var addressTrits = [];

    var kerl = new Kerl();

    kerl.initialize();
    kerl.absorb(digests, 0, digests.length);
    kerl.squeeze(addressTrits, 0, Curl.HASH_LENGTH);

    return addressTrits;
}

/**
*
*
**/
var digest = function(normalizedBundleFragment, signatureFragment) {

    var buffer = []

    var kerl = new Kerl();

    kerl.initialize();

    for (var i = 0; i< 27; i++) {
        buffer = signatureFragment.slice(i * 243, (i + 1) * 243);

        for (var j = normalizedBundleFragment[i] + 13; j-- > 0; ) {

            var jKerl = new Kerl();

            jKerl.initialize();
            jKerl.absorb(buffer, 0, buffer.length);
            jKerl.squeeze(buffer, 0, Curl.HASH_LENGTH);
        }

        kerl.absorb(buffer, 0, buffer.length);
    }

    kerl.squeeze(buffer, 0, Curl.HASH_LENGTH);
    return buffer;
}

/**
*
*
**/
var signatureFragment = function(normalizedBundleFragment, keyFragment) {

    var signatureFragment = keyFragment.slice(), hash = [];

    var kerl = new Kerl();

    for (var i = 0; i < 27; i++) {

        hash = signatureFragment.slice(i * 243, (i + 1) * 243);

        for (var j = 0; j < 13 - normalizedBundleFragment[i]; j++) {

            kerl.initialize();
            kerl.reset();
            kerl.absorb(hash, 0, hash.length);
            kerl.squeeze(hash, 0, Curl.HASH_LENGTH);
        }

        for (var j = 0; j < 243; j++) {

            signatureFragment[i * 243 + j] = hash[j];
        }
    }

    return signatureFragment;
}

/**
*
*
**/
var validateSignatures = function(expectedAddress, signatureFragments, bundleHash) {
    if (!bundleHash) {
        throw errors.invalidBundleHash();
    }

    var self = this;
    var bundle = new Bundle();

    var normalizedBundleFragments = [];
    var normalizedBundleHash = bundle.normalizedBundle(bundleHash);

    // Split hash into 3 fragments
    for (var i = 0; i < 3; i++) {
        normalizedBundleFragments[i] = normalizedBundleHash.slice(i * 27, (i + 1) * 27);
    }

    // Get digests
    var digests = [];

    for (var i = 0; i < signatureFragments.length; i++) {

        var digestBuffer = digest(normalizedBundleFragments[i % 3], Converter.trits(signatureFragments[i]));

        for (var j = 0; j < 243; j++) {

            digests[i * 243 + j] = digestBuffer[j]
        }
    }

    var address = Converter.trytes(self.address(digests));

    return (expectedAddress === address);
}


module.exports = {
    key                 : key,
    digests             : digests,
    address             : address,
    digest              : digest,
    signatureFragment   : signatureFragment,
    validateSignatures  : validateSignatures
}


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/errors/inputErrors.js":
/*!***************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/errors/inputErrors.js ***!
  \***************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {


module.exports = {

    invalidTrytes: function() {
        return new Error("Invalid Trytes provided");
    },
    invalidSeed: function() {
        return new Error("Invalid Seed provided");
    },
    invalidIndex: function() {
        return new Error("Invalid Index option provided");
    }, 
    invalidSecurity: function() {
        return new Error("Invalid Security option provided");
    },
    invalidChecksum: function(address) {
        return new Error("Invalid Checksum supplied for address: " + address)
    },
    invalidAttachedTrytes: function() {
        return new Error("Invalid attached Trytes provided");
    },
    invalidTransfers: function() {
        return new Error("Invalid transfers object");
    },
    invalidKey: function() {
        return new Error("You have provided an invalid key value");
    },
    invalidTrunkOrBranch: function(hash) {
        return new Error("You have provided an invalid hash as a trunk/branch: " + hash);
    },
    invalidUri: function(uri) {
        return new Error("You have provided an invalid URI for your Neighbor: " + uri)
    },
    notInt: function() {
        return new Error("One of your inputs is not an integer");
    },
    invalidInputs: function() {
        return new Error("Invalid inputs provided");
    }
}


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/iota.crypto.js":
/*!********************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/iota.crypto.js ***!
  \********************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

module.exports = {
  curl: __webpack_require__(/*! ./crypto/curl/curl */ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js"),
  kerl: __webpack_require__(/*! ./crypto/kerl/kerl */ "./node_modules/iota.crypto.js/lib/crypto/kerl/kerl.js"),
  bundle: __webpack_require__(/*! ./crypto/bundle/bundle */ "./node_modules/iota.crypto.js/lib/crypto/bundle/bundle.js"),
  converter: __webpack_require__(/*! ./crypto/converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js"),
  signing: __webpack_require__(/*! ./crypto/signing/signing */ "./node_modules/iota.crypto.js/lib/crypto/signing/signing.js"),
  oldSigning: __webpack_require__(/*! ./crypto/signing/oldSigning */ "./node_modules/iota.crypto.js/lib/crypto/signing/oldSigning.js"),
  hmac: __webpack_require__(/*! ./crypto/hmac/hmac */ "./node_modules/iota.crypto.js/lib/crypto/hmac/hmac.js"),
  multisig: __webpack_require__(/*! ./multisig/multisig */ "./node_modules/iota.crypto.js/lib/multisig/multisig.js"),
  utils: __webpack_require__(/*! ./utils/utils */ "./node_modules/iota.crypto.js/lib/utils/utils.js"),
  valid: __webpack_require__(/*! ./errors/inputErrors */ "./node_modules/iota.crypto.js/lib/errors/inputErrors.js"),
  add: __webpack_require__(/*! ./crypto/helpers/adder */ "./node_modules/iota.crypto.js/lib/crypto/helpers/adder.js")
}


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/multisig/address.js":
/*!*************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/multisig/address.js ***!
  \*************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var Converter      =  __webpack_require__(/*! ../crypto/converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js");
var Curl           =  __webpack_require__(/*! ../crypto/curl/curl */ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js");
var Kerl           =  __webpack_require__(/*! ../crypto/kerl/kerl */ "./node_modules/iota.crypto.js/lib/crypto/kerl/kerl.js");
var Signing        =  __webpack_require__(/*! ../crypto/signing/signing */ "./node_modules/iota.crypto.js/lib/crypto/signing/signing.js");
var Utils          =  __webpack_require__(/*! ../utils/utils */ "./node_modules/iota.crypto.js/lib/utils/utils.js");
var inputValidator =  __webpack_require__(/*! ../utils/inputValidator */ "./node_modules/iota.crypto.js/lib/utils/inputValidator.js");


/**
*   Initializes a new multisig address
*
*   @method addDigest
*   @param {string|array} digest digest trytes
*   @return {object} address instance
*
**/
function Address(digests) {

  if (!(this instanceof Address)) {
    return new Address(digests);
  }

  // Initialize kerl instance
  this._kerl = new Kerl();
  this._kerl.initialize();


  // Add digests if any
  if (digests) {

    this.absorb(digests);
  }
}

/**
*   Absorbs key digests
*
*   @method absorb
*   @param {string|array} digest digest trytes
*   @return {object} address instance
*
**/
Address.prototype.absorb = function (digest) {

  // Construct array
  var digests = Array.isArray(digest) ? digest : [digest];

  // Add digests
  for (var i = 0; i < digests.length; i++) {

    // Get trits of digest
    var digestTrits = Converter.trits(digests[i]);

    // Absorb digest
    this._kerl.absorb(digestTrits, 0, digestTrits.length);
  }

  return this;
}

/**
*   Finalizes and returns the multisig address in trytes
*
*   @method finalize
*   @param {string} digest digest trytes, optional
*   @return {string} address trytes
*
**/
Address.prototype.finalize = function (digest) {

    // Absorb last digest if provided
    if (digest) {
      this.absorb(digest);
    }

    // Squeeze the address trits
    var addressTrits = [];
    this._kerl.squeeze(addressTrits, 0, Curl.HASH_LENGTH);

    // Convert trits into trytes and return the address
    return Converter.trytes(addressTrits);
}


module.exports = Address;


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/multisig/multisig.js":
/*!**************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/multisig/multisig.js ***!
  \**************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var Signing         =  __webpack_require__(/*! ../crypto/signing/signing */ "./node_modules/iota.crypto.js/lib/crypto/signing/signing.js");
var Converter       =  __webpack_require__(/*! ../crypto/converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js");
var Kerl            =  __webpack_require__(/*! ../crypto/kerl/kerl */ "./node_modules/iota.crypto.js/lib/crypto/kerl/kerl.js");
var Curl            =  __webpack_require__(/*! ../crypto/curl/curl */ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js");
var Bundle          =  __webpack_require__(/*! ../crypto/bundle/bundle */ "./node_modules/iota.crypto.js/lib/crypto/bundle/bundle.js");
var Utils           =  __webpack_require__(/*! ../utils/utils */ "./node_modules/iota.crypto.js/lib/utils/utils.js");
var inputValidator  =  __webpack_require__(/*! ../utils/inputValidator */ "./node_modules/iota.crypto.js/lib/utils/inputValidator.js");
var errors          =  __webpack_require__(/*! ../errors/inputErrors */ "./node_modules/iota.crypto.js/lib/errors/inputErrors.js");
var Address         =  __webpack_require__(/*! ./address */ "./node_modules/iota.crypto.js/lib/multisig/address.js");

function Multisig(provider) {

    this._makeRequest = provider;
}


/**
*   Gets the key value of a seed
*
*   @method getKey
*   @param {string} seed
*   @param {int} index
*   @param {int} security Security level to be used for the private key / address. Can be 1, 2 or 3
*   @returns {string} digest trytes
**/
Multisig.getKey = function(seed, index, security) {

    return Converter.trytes(Signing.key(Converter.trits(seed), index, security));
}

/**
*   Gets the digest value of a seed
*
*   @method getDigest
*   @param {string} seed
*   @param {int} index
*   @param {int} security Security level to be used for the private key / address. Can be 1, 2 or 3
*   @returns {string} digest trytes
**/
Multisig.getDigest = function(seed, index, security) {

    var key = Signing.key(Converter.trits(seed), index, security);
    return Converter.trytes(Signing.digests(key));
}

/**
*   Multisig address constructor
*/
Multisig.address = Address;

/**
*   Validates  a generated multisig address
*
*   @method validateAddress
*   @param {string} multisigAddress
*   @param {array} digests
*   @returns {bool}
**/
Multisig.validateAddress = function(multisigAddress, digests) {

    var kerl = new Kerl();

    // initialize Kerl with the provided state
    kerl.initialize();

    // Absorb all key digests
    digests.forEach(function(keyDigest) {
        var trits = Converter.trits(keyDigest);
        kerl.absorb(Converter.trits(keyDigest), 0, trits.length);
    })

    // Squeeze address trits
    var addressTrits = [];
    kerl.squeeze(addressTrits, 0, Curl.HASH_LENGTH);

    // Convert trits into trytes and return the address
    return Converter.trytes(addressTrits) === multisigAddress;
}


/**
*   Prepares transfer by generating the bundle with the corresponding cosigner transactions
*   Does not contain signatures
*
*   @method initiateTransfer
*   @param {object} input the input addresses as well as the securitySum, and balance
*                   where `address` is the input multisig address
*                   and `securitySum` is the sum of security levels used by all co-signers
*                   and `balance` is the expected balance, if you wish to override getBalances
*   @param {string} remainderAddress Has to be generated by the cosigners before initiating the transfer, can be null if fully spent
*   @param {object} transfers
*   @param {function} callback
*   @returns {array} Array of transaction objects
**/
Multisig.initiateTransfer = function(input, remainderAddress, transfers, callback) {

    var self = this;

    // If message or tag is not supplied, provide it
    // Also remove the checksum of the address if it's there
    transfers.forEach(function(thisTransfer) {
        thisTransfer.message = thisTransfer.message ? thisTransfer.message : '';
        thisTransfer.tag = thisTransfer.tag ? thisTransfer.tag : '';
        thisTransfer.obsoleteTag = thisTransfer.obsoleteTag ? thisTransfer.obsoleteTag : '';        
        thisTransfer.address = Utils.noChecksum(thisTransfer.address);
    })

    // Input validation of transfers object
    if (!inputValidator.isTransfersArray(transfers)) {
        return callback(errors.invalidTransfers());
    }

    // check if int
    if (!inputValidator.isValue(input.securitySum)) {
        return callback(errors.invalidInputs());
    }

    // validate input address
    if (!inputValidator.isAddress(input.address)) {
        return callback(errors.invalidTrytes());
    }

    // validate remainder address
    if (remainderAddress && !inputValidator.isAddress(remainderAddress)) {
        return callback(errors.invalidTrytes());
    }

    // Create a new bundle
    var bundle = new Bundle();

    var totalValue = 0;
    var signatureFragments = [];
    var tag;

    //
    //  Iterate over all transfers, get totalValue
    //  and prepare the signatureFragments, message and tag
    //
    for (var i = 0; i < transfers.length; i++) {

        var signatureMessageLength = 1;

        // If message longer than 2187 trytes, increase signatureMessageLength (add multiple transactions)
        if (transfers[i].message.length > 2187) {

            // Get total length, message / maxLength (2187 trytes)
            signatureMessageLength += Math.floor(transfers[i].message.length / 2187);

            var msgCopy = transfers[i].message;

            // While there is still a message, copy it
            while (msgCopy) {

                var fragment = msgCopy.slice(0, 2187);
                msgCopy = msgCopy.slice(2187, msgCopy.length);

                // Pad remainder of fragment
                for (var j = 0; fragment.length < 2187; j++) {
                    fragment += '9';
                }

                signatureFragments.push(fragment);
            }

        } else {
            // Else, get single fragment with 2187 of 9's trytes
            var fragment = '';

            if (transfers[i].message) {
                fragment = transfers[i].message.slice(0, 2187)
            }

            for (var j = 0; fragment.length < 2187; j++) {
                fragment += '9';
            }

            signatureFragments.push(fragment);
        }

        // get current timestamp in seconds
        var timestamp = Math.floor(Date.now() / 1000);

        // If no tag defined, get 27 tryte tag.
        tag = transfers[i].tag ? transfers[i].tag : '999999999999999999999999999';

        // Pad for required 27 tryte length
        for (var j = 0; tag.length < 27; j++) {
            tag += '9';
        }

        // Add first entries to the bundle
        // Slice the address in case the user provided a checksummed one
        bundle.addEntry(signatureMessageLength, transfers[i].address.slice(0, 81), transfers[i].value, tag, timestamp);

        // Sum up total value
        totalValue += parseInt(transfers[i].value);
    }

    // Get inputs if we are sending tokens
    if (totalValue) {

        function createBundle(totalBalance, callback) {
            if (totalBalance > 0) {

                var toSubtract = 0 - totalBalance;
                var timestamp = Math.floor(Date.now() / 1000);

                // Add input as bundle entry
                // Only a single entry, signatures will be added later
                bundle.addEntry(input.securitySum, input.address, toSubtract, tag, timestamp);
            }

            if (totalValue > totalBalance) {
                return callback(new Error("Not enough balance."));
            }


            // If there is a remainder value
            // Add extra output to send remaining funds to
            if (totalBalance > totalValue) {

                var remainder = totalBalance - totalValue;

                // Remainder bundle entry if necessary
                if (!remainderAddress) {
                    return callback(new Error("No remainder address defined"));
                }

                bundle.addEntry(1, remainderAddress, remainder, tag, timestamp);
            }

            bundle.finalize();
            bundle.addTrytes(signatureFragments);

            return callback(null, bundle.bundle);
        };

        if (input.balance) {
          createBundle(input.balance, callback);
        } else {
          var command = {
              'command': 'getBalances',
              'addresses': new Array(input.address),
              'threshold': 100
          }
          self._makeRequest.send(command, function(e, balances) {
              if (e) return callback(e);
              createBundle(parseInt(balances.balances[0]), callback);
          });
        }

    } else {

        return callback(new Error("Invalid value transfer: the transfer does not require a signature."));
    }

}


/**
*   Adds the cosigner signatures to the corresponding bundle transaction
*
*   @method addSignature
*   @param {array} bundleToSign
*   @param {int} cosignerIndex
*   @param {string} inputAddress
*   @param {string} key
*   @param {function} callback
*   @returns {array} trytes Returns bundle trytes
**/
Multisig.addSignature = function(bundleToSign, inputAddress, key, callback) {

    var bundle = new Bundle();
    bundle.bundle = bundleToSign;

    // Get the security used for the private key
    // 1 security level = 2187 trytes
    var security = (key.length / 2187);

    // convert private key trytes into trits
    var key = Converter.trits(key);


    // First get the total number of already signed transactions
    // use that for the bundle hash calculation as well as knowing
    // where to add the signature
    var numSignedTxs = 0;

    for (var i = 0; i < bundle.bundle.length; i++) {

        if (bundle.bundle[i].address === inputAddress) {

            // If transaction is already signed, increase counter
            if (!inputValidator.isNinesTrytes(bundle.bundle[i].signatureMessageFragment)) {

                numSignedTxs++;
            }
            // Else sign the transactionse
            else {

                var bundleHash = bundle.bundle[i].bundle;

                //  First 6561 trits for the firstFragment
                var firstFragment = key.slice(0, 6561);

                //  Get the normalized bundle hash
                var normalizedBundleHash = bundle.normalizedBundle(bundleHash);
                var normalizedBundleFragments = [];

                // Split hash into 3 fragments
                for (var k = 0; k < 3; k++) {
                    normalizedBundleFragments[k] = normalizedBundleHash.slice(k * 27, (k + 1) * 27);
                }

                //  First bundle fragment uses 27 trytes
                var firstBundleFragment = normalizedBundleFragments[numSignedTxs % 3];

                //  Calculate the new signatureFragment with the first bundle fragment
                var firstSignedFragment = Signing.signatureFragment(firstBundleFragment, firstFragment);

                //  Convert signature to trytes and assign the new signatureFragment
                bundle.bundle[i].signatureMessageFragment = Converter.trytes(firstSignedFragment);

                for (var j = 1; j < security; j++) {

                    //  Next 6561 trits for the firstFragment
                    var nextFragment = key.slice(6561 * j, (j + 1) * 6561);

                    //  Use the next 27 trytes
                    var nextBundleFragment = normalizedBundleFragments[(numSignedTxs + j) % 3];

                    //  Calculate the new signatureFragment with the first bundle fragment
                    var nextSignedFragment = Signing.signatureFragment(nextBundleFragment, nextFragment);

                    //  Convert signature to trytes and add new bundle entry at i + j position
                    // Assign the signature fragment
                    bundle.bundle[i + j].signatureMessageFragment = Converter.trytes(nextSignedFragment);
                }

                break;
            }
        }
    }

    return callback(null, bundle.bundle);
}

module.exports = Multisig;


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/utils/asciiToTrytes.js":
/*!****************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/utils/asciiToTrytes.js ***!
  \****************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

//
//  Conversion of ascii encoded bytes to trytes.
//  Input is a string (can be stringified JSON object), return value is Trytes
//
//  How the conversion works:
//    2 Trytes === 1 Byte
//    There are a total of 27 different tryte values: 9ABCDEFGHIJKLMNOPQRSTUVWXYZ
//
//    1. We get the decimal value of an individual ASCII character
//    2. From the decimal value, we then derive the two tryte values by basically calculating the tryte equivalent (e.g. 100 === 19 + 3 * 27)
//      a. The first tryte value is the decimal value modulo 27 (27 trytes)
//      b. The second value is the remainder (decimal value - first value), divided by 27
//    3. The two values returned from Step 2. are then input as indices into the available values list ('9ABCDEFGHIJKLMNOPQRSTUVWXYZ') to get the correct tryte value
//
//   EXAMPLES
//      Lets say we want to convert the ASCII character "Z".
//        1. 'Z' has a decimal value of 90.
//        2. 90 can be represented as 9 + 3 * 27. To make it simpler:
//           a. First value: 90 modulo 27 is 9. This is now our first value
//           b. Second value: (90 - 9) / 27 is 3. This is our second value.
//        3. Our two values are now 9 and 3. To get the tryte value now we simply insert it as indices into '9ABCDEFGHIJKLMNOPQRSTUVWXYZ'
//           a. The first tryte value is '9ABCDEFGHIJKLMNOPQRSTUVWXYZ'[9] === "I"
//           b. The second tryte value is '9ABCDEFGHIJKLMNOPQRSTUVWXYZ'[3] === "C"
//        Our tryte pair is "IC"
//
//      RESULT:
//        The ASCII char "Z" is represented as "IC" in trytes.
//
function toTrytes(input) {

    // If input is not a string, return null
    if ( typeof input !== 'string' ) return null

    var TRYTE_VALUES = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var trytes = "";

    for (var i = 0; i < input.length; i++) {
        var char = input[i];
        var asciiValue = char.charCodeAt(0);

        // If not recognizable ASCII character, return null
        if (asciiValue > 255) {
            //asciiValue = 32
            return null;
        }

        var firstValue = asciiValue % 27;
        var secondValue = (asciiValue - firstValue) / 27;

        var trytesValue = TRYTE_VALUES[firstValue] + TRYTE_VALUES[secondValue];

        trytes += trytesValue;
    }

    return trytes;
}


//
//  Trytes to bytes
//  Reverse operation from the byteToTrytes function in send.js
//  2 Trytes == 1 Byte
//  We assume that the trytes are a JSON encoded object thus for our encoding:
//    First character = {
//    Last character = }
//    Everything after that is 9's padding
//
function fromTrytes(inputTrytes) {

    // If input is not a string, return null
    if ( typeof inputTrytes !== 'string' ) return null

    // If input length is odd, return null
    if ( inputTrytes.length % 2 ) return null

    var TRYTE_VALUES = "9ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    var outputString = "";

    for (var i = 0; i < inputTrytes.length; i += 2) {
        // get a trytes pair
        var trytes = inputTrytes[i] + inputTrytes[i + 1];

        var firstValue = TRYTE_VALUES.indexOf(trytes[0]);
        var secondValue = TRYTE_VALUES.indexOf(trytes[1]);

        var decimalValue = firstValue + secondValue * 27;

        var character = String.fromCharCode(decimalValue);

        outputString += character;
    }

    return outputString;
}

module.exports = {
    toTrytes: toTrytes,
    fromTrytes: fromTrytes
}


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/utils/extractJson.js":
/*!**************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/utils/extractJson.js ***!
  \**************************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var ascii = __webpack_require__(/*! ./asciiToTrytes */ "./node_modules/iota.crypto.js/lib/utils/asciiToTrytes.js");
var inputValidator = __webpack_require__(/*! ./inputValidator */ "./node_modules/iota.crypto.js/lib/utils/inputValidator.js");

/**
*   extractJson takes a bundle as input and from the signatureMessageFragments extracts the correct JSON
*   data which was encoded and sent with the transaction.
*
*   @method extractJson
*   @param {array} bundle
*   @returns {Object}
**/
function extractJson(bundle) {

    // if wrong input return null
    if ( !inputValidator.isArray(bundle) || bundle[0] === undefined ) return null;


    // Sanity check: if the first tryte pair is not opening bracket, it's not a message
    var firstTrytePair = bundle[0].signatureMessageFragment[0] + bundle[0].signatureMessageFragment[1];

    if (firstTrytePair !== "OD") return null;

    var index = 0;
    var notEnded = true;
    var trytesChunk = '';
    var trytesChecked = 0;
    var preliminaryStop = false;
    var finalJson = '';

    while (index < bundle.length && notEnded) {

        var messageChunk = bundle[index].signatureMessageFragment;

        // We iterate over the message chunk, reading 9 trytes at a time
        for (var i = 0; i < messageChunk.length; i += 9) {

            // get 9 trytes
            var trytes = messageChunk.slice(i, i + 9);
            trytesChunk += trytes;

            // Get the upper limit of the tytes that need to be checked
            // because we only check 2 trytes at a time, there is sometimes a leftover
            var upperLimit = trytesChunk.length - trytesChunk.length % 2;

            var trytesToCheck = trytesChunk.slice(trytesChecked, upperLimit);

            // We read 2 trytes at a time and check if it equals the closing bracket character
            for (var j = 0; j < trytesToCheck.length; j += 2) {

                var trytePair = trytesToCheck[j] + trytesToCheck[j + 1];

                // If closing bracket char was found, and there are only trailing 9's
                // we quit and remove the 9's from the trytesChunk.
                if ( preliminaryStop && trytePair === '99' ) {

                    notEnded = false;
                    // TODO: Remove the trailing 9's from trytesChunk
                    //var closingBracket = trytesToCheck.indexOf('QD') + 1;

                    //trytesChunk = trytesChunk.slice( 0, ( trytesChunk.length - trytesToCheck.length ) + ( closingBracket % 2 === 0 ? closingBracket : closingBracket + 1 ) );

                    break;
                }

                finalJson += ascii.fromTrytes(trytePair);

                // If tryte pair equals closing bracket char, we set a preliminary stop
                // the preliminaryStop is useful when we have a nested JSON object
                if (trytePair === "QD") {
                    preliminaryStop = true;
                }
            }

            if (!notEnded)
                break;

            trytesChecked += trytesToCheck.length;
        }

        // If we have not reached the end of the message yet, we continue with the next
        // transaction in the bundle
        index += 1;

    }

    // If we did not find any JSON, return null
    if (notEnded) {

        return null;

    } else {

        return finalJson;

    }
}

module.exports = extractJson;


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/utils/inputValidator.js":
/*!*****************************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/utils/inputValidator.js ***!
  \*****************************************************************/
/*! no static exports found */
/***/ (function(module, exports) {

/**
*   checks if input is correct address
*
*   @method isAddress
*   @param {string} address
*   @returns {boolean}
**/
var isAddress = function(address) {
    // TODO: In the future check checksum

    // Check if address with checksum
    if (address.length === 90) {

        if (!isTrytes(address, 90)) {
            return false;
        }
    } else {

        if (!isTrytes(address, 81)) {
            return false;
        }
    }

    return true;
}

/**
*   checks if input is correct trytes consisting of A-Z9
*   optionally validate length
*
*   @method isTrytes
*   @param {string} trytes
*   @param {integer} length optional
*   @returns {boolean}
**/
var isTrytes = function(trytes, length) {

    // If no length specified, just validate the trytes
    if (!length) length = "0,"

    var regexTrytes = new RegExp("^[9A-Z]{" + length +"}$");
    return regexTrytes.test(trytes) && isString(trytes);
}

/**
*   checks if input is correct trytes consisting of A-Z9
*   optionally validate length
*
*   @method isNinesTrytes
*   @param {string} trytes
*   @returns {boolean}
**/
var isNinesTrytes = function(trytes) {

    return /^[9]+$/.test(trytes) && isString(trytes);
}

/**
*   checks if integer value
*
*   @method isValue
*   @param {string} value
*   @returns {boolean}
**/
var isValue = function(value) {

    // check if correct number
    return Number.isInteger(value)
}

/**
*   checks whether input is a value or not. Can be a string, float or integer
*
*   @method isNum
*   @param {int}
*   @returns {boolean}
**/
var isNum = function(input) {

    return /^(\d+\.?\d{0,15}|\.\d{0,15})$/.test(input);
}

/**
*   checks if input is correct hash
*
*   @method isHash
*   @param {string} hash
*   @returns {boolean}
**/
var isHash = function(hash) {

    // Check if valid, 81 trytes
    if (!isTrytes(hash, 81)) {

        return false;
    }

    return true;
}

/**
*   checks whether input is a string or not
*
*   @method isString
*   @param {string}
*   @returns {boolean}
**/
var isString = function(string) {

    return typeof string === 'string';
}


/**
*   checks whether input is an array or not
*
*   @method isArray
*   @param {object}
*   @returns {boolean}
**/
var isArray = function(array) {

    return array instanceof Array;
}


/**
*   checks whether input is object or not
*
*   @method isObject
*   @param {object}
*   @returns {boolean}
**/
var isObject = function(object) {

    return typeof object === 'object';
}



/**
*   checks if input is correct hash
*
*   @method isTransfersArray
*   @param {array} hash
*   @returns {boolean}
**/
var isTransfersArray = function(transfersArray) {

    if (!isArray(transfersArray)) return false;

    for (var i = 0; i < transfersArray.length; i++) {

        var transfer = transfersArray[i];

        // Check if valid address
        var address = transfer.address;
        if (!isAddress(address)) {
            return false;
        }

        // Validity check for value
        var value = transfer.value;
        if (!isValue(value)) {
            return false;
        }

        // Check if message is correct trytes of any length
        var message = transfer.message;
        if (!isTrytes(message, "0,")) {
            return false;
        }

        // Check if tag is correct trytes of {0,27} trytes
        var tag = transfer.tag || transfer.obsoleteTag;
        if (!isTrytes(tag, "0,27")) {
            return false;
        }

    }

    return true;
}

/**
*   checks if input is list of correct trytes
*
*   @method isArrayOfHashes
*   @param {list} hashesArray
*   @returns {boolean}
**/
var isArrayOfHashes = function(hashesArray) {

    if (!isArray(hashesArray)) return false;

    for (var i = 0; i < hashesArray.length; i++) {

        var hash = hashesArray[i];

        // Check if address with checksum
        if (hash.length === 90) {

            if (!isTrytes(hash, 90)) {
                return false;
            }
        } else {

            if (!isTrytes(hash, 81)) {
                return false;
            }
        }
    }

    return true;
}

/**
*   checks if input is list of correct trytes
*
*   @method isArrayOfTrytes
*   @param {list} trytesArray
*   @returns {boolean}
**/
var isArrayOfTrytes = function(trytesArray) {

    if (!isArray(trytesArray)) return false;

    for (var i = 0; i < trytesArray.length; i++) {

        var tryteValue = trytesArray[i];

        // Check if correct 2673 trytes
        if (!isTrytes(tryteValue, 2673)) {
            return false;
        }
    }

    return true;
}

/**
*   checks if attached trytes if last 241 trytes are non-zero
*
*   @method isArrayOfAttachedTrytes
*   @param {array} trytesArray
*   @returns {boolean}
**/
var isArrayOfAttachedTrytes = function(trytesArray) {

    if (!isArray(trytesArray)) return false;

    for (var i = 0; i < trytesArray.length; i++) {

        var tryteValue = trytesArray[i];

        // Check if correct 2673 trytes
        if (!isTrytes(tryteValue, 2673)) {
            return false;
        }

        var lastTrytes = tryteValue.slice(2673 - (3 * 81));

        if (/^[9]+$/.test(lastTrytes)) {
            return false;
        }
    }

    return true;
}

/**
*   checks if correct bundle with transaction object
*
*   @method isArrayOfTxObjects
*   @param {array} bundle
*   @returns {boolean}
**/
var isArrayOfTxObjects = function(bundle) {

    if (!isArray(bundle) || bundle.length === 0) return false;

    var validArray = true;

    bundle.forEach(function(txObject) {

        var keysToValidate = [
            {
                key: 'hash',
                validator: isHash,
                args: null
            }, {
                key: 'signatureMessageFragment',
                validator: isTrytes,
                args: 2187
            }, {
                key: 'address',
                validator: isHash,
                args: null
            }, {
                key: 'value',
                validator: isValue,
                args: null
            }, {
                key: 'obsoleteTag',
                validator: isTrytes,
                args: 27
            }, {
                key: 'timestamp',
                validator: isValue,
                args: null
            }, {
                key: 'currentIndex',
                validator: isValue,
                args: null
            },{
                key: 'lastIndex',
                validator: isValue,
                args: null
            }, {
                key: 'bundle',
                validator: isHash,
                args: null
            }, {
                key: 'trunkTransaction',
                validator: isHash,
                args: null
            }, {
                key: 'branchTransaction',
                validator: isHash,
                args: null
            }, {
                key: 'tag',
                validator: isTrytes,
                args: 27
            }, {
                key: 'attachmentTimestamp',
                validator: isValue,
                args: null
            }, {
                key: 'attachmentTimestampLowerBound',
                validator: isValue,
                args: null
            }, {
                key: 'attachmentTimestampUpperBound',
                validator: isValue,
                args: null
            }, {
                key: 'nonce',
                validator: isTrytes,
                args: 27
            }
        ]

        for (var i = 0; i < keysToValidate.length; i++) {

            var key = keysToValidate[i].key;
            var validator = keysToValidate[i].validator;
            var args = keysToValidate[i].args

            // If input does not have keyIndex and address, return false
            if (!txObject.hasOwnProperty(key)) {
                validArray = false;
                break;
            }

            // If input validator function does not return true, exit
            if (!validator(txObject[key], args)) {
                validArray = false;
                break;
            }
        }
    })

    return validArray;
}

/**
*   checks if correct inputs list
*
*   @method isInputs
*   @param {array} inputs
*   @returns {boolean}
**/
var isInputs = function(inputs) {

    if (!isArray(inputs)) return false;

    for (var i = 0; i < inputs.length; i++) {

        var input = inputs[i];

        // If input does not have keyIndex and address, return false
        if (!input.hasOwnProperty('security') || !input.hasOwnProperty('keyIndex') || !input.hasOwnProperty('address')) return false;

        if (!isAddress(input.address)) {
            return false;
        }

        if (!isValue(input.security)) {
            return false;
        }

        if (!isValue(input.keyIndex)) {
            return false;
        }
    }

    return true;
}

/**
*   Checks that a given uri is valid
*
*   Valid Examples:
*   udp://[2001:db8:a0b:12f0::1]:14265
*   udp://[2001:db8:a0b:12f0::1]
*   udp://8.8.8.8:14265
*   udp://domain.com
*   udp://domain2.com:14265
*
*   @method isUri
*   @param {string} node
*   @returns {bool} valid
**/
var isUri = function(node) {

    var getInside = /^(udp|tcp):\/\/([\[][^\]\.]*[\]]|[^\[\]:]*)[:]{0,1}([0-9]{1,}$|$)/i;

    var stripBrackets = /[\[]{0,1}([^\[\]]*)[\]]{0,1}/;

    var uriTest = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))|(^\s*((?=.{1,255}$)(?=.*[A-Za-z].*)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?)*)\s*$)/;

    if(!getInside.test(node)) {
        return false;
    }

    return uriTest.test(stripBrackets.exec(getInside.exec(node)[1])[1]);
}

module.exports = {
    isAddress: isAddress,
    isTrytes: isTrytes,
    isNinesTrytes: isNinesTrytes,
    isValue: isValue,
    isHash: isHash,
    isTransfersArray: isTransfersArray,
    isArrayOfHashes: isArrayOfHashes,
    isArrayOfTrytes: isArrayOfTrytes,
    isArrayOfAttachedTrytes: isArrayOfAttachedTrytes,
    isArrayOfTxObjects: isArrayOfTxObjects,
    isInputs: isInputs,
    isString: isString,
    isNum: isNum,
    isArray: isArray,
    isObject: isObject,
    isUri: isUri
}


/***/ }),

/***/ "./node_modules/iota.crypto.js/lib/utils/utils.js":
/*!********************************************************!*\
  !*** ./node_modules/iota.crypto.js/lib/utils/utils.js ***!
  \********************************************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

var inputValidator  =   __webpack_require__(/*! ./inputValidator */ "./node_modules/iota.crypto.js/lib/utils/inputValidator.js");
var Curl            =   __webpack_require__(/*! ../crypto/curl/curl */ "./node_modules/iota.crypto.js/lib/crypto/curl/curl.js");
var Kerl            =   __webpack_require__(/*! ../crypto/kerl/kerl */ "./node_modules/iota.crypto.js/lib/crypto/kerl/kerl.js");
var Converter       =   __webpack_require__(/*! ../crypto/converter/converter */ "./node_modules/iota.crypto.js/lib/crypto/converter/converter.js");
var Signing         =   __webpack_require__(/*! ../crypto/signing/signing */ "./node_modules/iota.crypto.js/lib/crypto/signing/signing.js");
var CryptoJS        =   __webpack_require__(/*! crypto-js */ "./node_modules/crypto-js/index.js");
var ascii           =   __webpack_require__(/*! ./asciiToTrytes */ "./node_modules/iota.crypto.js/lib/utils/asciiToTrytes.js");
var extractJson     =   __webpack_require__(/*! ./extractJson */ "./node_modules/iota.crypto.js/lib/utils/extractJson.js");


/**
*   Table of IOTA Units based off of the standard System of Units
**/
var unitMap = {
    'i'   :   1,
    'Ki'  :   1000,
    'Mi'  :   1000000,
    'Gi'  :   1000000000,
    'Ti'  :   1000000000000,
    'Pi'  :   1000000000000000  // For the very, very rich
}

/**
*   converts IOTA units
*
*   @method convertUnits
*   @param {string || int || float} value
*   @param {string} fromUnit
*   @param {string} toUnit
*   @returns {integer} converted
**/
var convertUnits = function(value, fromUnit, toUnit) {

    // Check if wrong unit provided
    if (unitMap[fromUnit] === undefined || unitMap[toUnit] === undefined) {

        throw new Error("Invalid unit provided");
    }

    var afterComma = String(value).match(/\.([\d]+)$/);

    if (afterComma && afterComma[1].length > String(unitMap[fromUnit]).length - 1) {

        throw new Error("Too many digits after comma");
    }

    // If not valid value, throw error
    if (!inputValidator.isNum(value)) {

        throw new Error("Invalid value");
    }


    var floatValue = parseFloat(value);

    var converted = (floatValue * unitMap[fromUnit]) / unitMap[toUnit];

    return converted;
}

/**
*   Generates the 9-tryte checksum of an address
*
*   @method addChecksum
*   @param {string | list} inputValue
*   @param {int} checksumLength
@   @param {bool} isAddress default is true
*   @returns {string | list} address (with checksum)
**/
var addChecksum = function(inputValue, checksumLength, isAddress) {

    // checksum length is either user defined, or 9 trytes
    var checksumLength = checksumLength || 9;
    var isAddress = (isAddress !== false);

    // the length of the trytes to be validated
    var validationLength = isAddress ? 81 : null;

    var isSingleInput = inputValidator.isString( inputValue );

    // If only single address, turn it into an array
    if ( isSingleInput ) inputValue = new Array( inputValue );

    var inputsWithChecksum = [];

    inputValue.forEach(function(thisValue) {

        // check if correct trytes
        if (!inputValidator.isTrytes(thisValue, validationLength)) {
            throw new Error("Invalid input");
        }

        var kerl = new Kerl();
        kerl.initialize();

        // Address trits
        var addressTrits = Converter.trits(thisValue);

        // Checksum trits
        var checksumTrits = [];

        // Absorb address trits
        kerl.absorb(addressTrits, 0, addressTrits.length);

        // Squeeze checksum trits
        kerl.squeeze(checksumTrits, 0, Curl.HASH_LENGTH);

        // First 9 trytes as checksum
        var checksum = Converter.trytes( checksumTrits ).substring( 81 - checksumLength, 81 );
        inputsWithChecksum.push( thisValue + checksum );
    });

    if (isSingleInput) {

        return inputsWithChecksum[ 0 ];

    } else {

        return inputsWithChecksum;

    }
}

/**
*   Removes the 9-tryte checksum of an address
*
*   @method noChecksum
*   @param {string | list} address
*   @returns {string | list} address (without checksum)
**/
var noChecksum = function(address) {

    var isSingleAddress = inputValidator.isString(address)

    // If only single address, turn it into an array
    if (isSingleAddress) address = new Array(address);

    var addressesWithChecksum = [];

    address.forEach(function(thisAddress) {
        addressesWithChecksum.push(thisAddress.slice(0, 81))
    })

    // return either string or the list
    if (isSingleAddress) {

        return addressesWithChecksum[0];

    } else {

        return addressesWithChecksum;

    }
}

/**
*   Validates the checksum of an address
*
*   @method isValidChecksum
*   @param {string} addressWithChecksum
*   @returns {bool}
**/
var isValidChecksum = function(addressWithChecksum) {

    var addressWithoutChecksum = noChecksum(addressWithChecksum);

    var newChecksum = addChecksum(addressWithoutChecksum);

    return newChecksum === addressWithChecksum;
}

/**
*   Converts transaction trytes of 2673 trytes into a transaction object
*
*   @method transactionObject
*   @param {string} trytes
*   @returns {String} transactionObject
**/
var transactionObject = function(trytes) {

    if (!trytes) return;

    // validity check
    for (var i = 2279; i < 2295; i++) {

        if (trytes.charAt(i) !== "9") {

            return null;

        }
    }

    var thisTransaction = {};
    var transactionTrits = Converter.trits(trytes);
    var hash = [];

    var curl = new Curl();

    // generate the correct transaction hash
    curl.initialize();
    curl.absorb(transactionTrits, 0, transactionTrits.length);
    curl.squeeze(hash, 0, 243);

    thisTransaction.hash = Converter.trytes(hash);
    thisTransaction.signatureMessageFragment = trytes.slice(0, 2187);
    thisTransaction.address = trytes.slice(2187, 2268);
    thisTransaction.value = Converter.value(transactionTrits.slice(6804, 6837));
    thisTransaction.obsoleteTag = trytes.slice(2295, 2322);
    thisTransaction.timestamp = Converter.value(transactionTrits.slice(6966, 6993));
    thisTransaction.currentIndex = Converter.value(transactionTrits.slice(6993, 7020));
    thisTransaction.lastIndex = Converter.value(transactionTrits.slice(7020, 7047));
    thisTransaction.bundle = trytes.slice(2349, 2430);
    thisTransaction.trunkTransaction = trytes.slice(2430, 2511);
    thisTransaction.branchTransaction = trytes.slice(2511, 2592);

    thisTransaction.tag = trytes.slice(2592, 2619);
    thisTransaction.attachmentTimestamp = Converter.value(transactionTrits.slice(7857, 7884));
    thisTransaction.attachmentTimestampLowerBound = Converter.value(transactionTrits.slice(7884, 7911));
    thisTransaction.attachmentTimestampUpperBound = Converter.value(transactionTrits.slice(7911, 7938));
    thisTransaction.nonce = trytes.slice(2646, 2673);

    return thisTransaction;
}

/**
*   Converts a transaction object into trytes
*
*   @method transactionTrytes
*   @param {object} transactionTrytes
*   @returns {String} trytes
**/
var transactionTrytes = function(transaction) {

    var valueTrits = Converter.trits(transaction.value);
    while (valueTrits.length < 81) {
        valueTrits[valueTrits.length] = 0;
    }

    var timestampTrits = Converter.trits(transaction.timestamp);
    while (timestampTrits.length < 27) {
        timestampTrits[timestampTrits.length] = 0;
    }

    var currentIndexTrits = Converter.trits(transaction.currentIndex);
    while (currentIndexTrits.length < 27) {
        currentIndexTrits[currentIndexTrits.length] = 0;
    }

    var lastIndexTrits = Converter.trits(transaction.lastIndex);
    while (lastIndexTrits.length < 27) {
        lastIndexTrits[lastIndexTrits.length] = 0;
    }

    var attachmentTimestampTrits = Converter.trits(transaction.attachmentTimestamp || 0);
    while (attachmentTimestampTrits.length < 27) {
        attachmentTimestampTrits[attachmentTimestampTrits.length] = 0;
    }

    var attachmentTimestampLowerBoundTrits = Converter.trits(transaction.attachmentTimestampLowerBound || 0);
    while (attachmentTimestampLowerBoundTrits.length < 27) {
        attachmentTimestampLowerBoundTrits[attachmentTimestampLowerBoundTrits.length] = 0;
    }

    var attachmentTimestampUpperBoundTrits = Converter.trits(transaction.attachmentTimestampUpperBound || 0);
    while (attachmentTimestampUpperBoundTrits.length < 27) {
        attachmentTimestampUpperBoundTrits[attachmentTimestampUpperBoundTrits.length] = 0;
    }

    transaction.tag = transaction.tag || transaction.obsoleteTag;

    return transaction.signatureMessageFragment
    + transaction.address
    + Converter.trytes(valueTrits)
    + transaction.obsoleteTag
    + Converter.trytes(timestampTrits)
    + Converter.trytes(currentIndexTrits)
    + Converter.trytes(lastIndexTrits)
    + transaction.bundle
    + transaction.trunkTransaction
    + transaction.branchTransaction
    + transaction.tag
    + Converter.trytes(attachmentTimestampTrits)
    + Converter.trytes(attachmentTimestampLowerBoundTrits)
    + Converter.trytes(attachmentTimestampUpperBoundTrits)
    + transaction.nonce;
}

/**
*   Categorizes a list of transfers between sent and received
*
*   @method categorizeTransfers
*   @param {object} transfers Transfers (bundles)
*   @param {list} addresses List of addresses that belong to the user
*   @returns {String} trytes
**/
var categorizeTransfers = function(transfers, addresses) {

    var categorized = {
        'sent'      : [],
        'received'  : []
    }

    // Iterate over all bundles and sort them between incoming and outgoing transfers
    transfers.forEach(function(bundle) {

        var spentAlreadyAdded = false;

        // Iterate over every bundle entry
        bundle.forEach(function(bundleEntry, bundleIndex) {

            // If bundle address in the list of addresses associated with the seed
            // add the bundle to the
            if (addresses.indexOf(bundleEntry.address) > -1) {

                // Check if it's a remainder address
                var isRemainder = (bundleEntry.currentIndex === bundleEntry.lastIndex) && bundleEntry.lastIndex !== 0;

                // check if sent transaction
                if (bundleEntry.value < 0 && !spentAlreadyAdded && !isRemainder) {

                    categorized.sent.push(bundle);

                    // too make sure we do not add transactions twice
                    spentAlreadyAdded = true;
                }
                // check if received transaction, or 0 value (message)
                // also make sure that this is not a 2nd tx for spent inputs
                else if (bundleEntry.value >= 0 && !spentAlreadyAdded && !isRemainder) {

                    categorized.received.push(bundle);
                }
            }
        })
    })

    return categorized;
}


/**
*   Validates the signatures
*
*   @method validateSignatures
*   @param {array} signedBundle
*   @param {string} inputAddress
*   @returns {bool}
**/
var validateSignatures = function(signedBundle, inputAddress) {


    var bundleHash;
    var signatureFragments = [];

    for (var i = 0; i < signedBundle.length; i++) {

        if (signedBundle[i].address === inputAddress) {

            bundleHash = signedBundle[i].bundle;

            // if we reached remainder bundle
            if (inputValidator.isNinesTrytes(signedBundle[i].signatureMessageFragment)) {
                break;
            }

            signatureFragments.push(signedBundle[i].signatureMessageFragment)
        }
    }

    if (!bundleHash) {
        return false;
    }

    return Signing.validateSignatures(inputAddress, signatureFragments, bundleHash);
}


/**
*   Checks is a Bundle is valid. Validates signatures and overall structure. Has to be tail tx first.
*
*   @method isValidBundle
*   @param {array} bundle
*   @returns {bool} valid
**/
var isBundle = function(bundle) {

    // If not correct bundle
    if (!inputValidator.isArrayOfTxObjects(bundle)) return false;

    var totalSum = 0, lastIndex, bundleHash = bundle[0].bundle;

    // Prepare to absorb txs and get bundleHash
    var bundleFromTxs = [];

    var kerl = new Kerl();
    kerl.initialize();

    // Prepare for signature validation
    var signaturesToValidate = [];

    bundle.forEach(function(bundleTx, index) {

        totalSum += bundleTx.value;

        // currentIndex has to be equal to the index in the array
        if (bundleTx.currentIndex !== index) return false;

        // Get the transaction trytes
        var thisTxTrytes = transactionTrytes(bundleTx);

        // Absorb bundle hash + value + timestamp + lastIndex + currentIndex trytes.
        var thisTxTrits = Converter.trits(thisTxTrytes.slice(2187, 2187 + 162));
        kerl.absorb(thisTxTrits, 0, thisTxTrits.length);

        // Check if input transaction
        if (bundleTx.value < 0) {
            var thisAddress = bundleTx.address;

            var newSignatureToValidate = {
                'address': thisAddress,
                'signatureFragments': Array(bundleTx.signatureMessageFragment)
            }

            // Find the subsequent txs with the remaining signature fragment
            for (var i = index; i < bundle.length - 1; i++) {
                var newBundleTx = bundle[i + 1];

                // Check if new tx is part of the signature fragment
                if (newBundleTx.address === thisAddress && newBundleTx.value === 0) {
                    newSignatureToValidate.signatureFragments.push(newBundleTx.signatureMessageFragment);
                }
            }

            signaturesToValidate.push(newSignatureToValidate);
        }
    });

    // Check for total sum, if not equal 0 return error
    if (totalSum !== 0) return false;

    // get the bundle hash from the bundle transactions
    kerl.squeeze(bundleFromTxs, 0, Curl.HASH_LENGTH);
    var bundleFromTxs = Converter.trytes(bundleFromTxs);

    // Check if bundle hash is the same as returned by tx object
    if (bundleFromTxs !== bundleHash) return false;

    // Last tx in the bundle should have currentIndex === lastIndex
    if (bundle[bundle.length - 1].currentIndex !== bundle[bundle.length - 1].lastIndex) return false;

    // Validate the signatures
    for (var i = 0; i < signaturesToValidate.length; i++) {

        var isValidSignature = Signing.validateSignatures(signaturesToValidate[i].address, signaturesToValidate[i].signatureFragments, bundleHash);

        if (!isValidSignature) return false;
    }

    return true;
}

module.exports = {
    inputValidator      : inputValidator,    
    convertUnits        : convertUnits,
    addChecksum         : addChecksum,
    noChecksum          : noChecksum,
    isValidChecksum     : isValidChecksum,
    transactionObject   : transactionObject,
    transactionTrytes   : transactionTrytes,
    categorizeTransfers : categorizeTransfers,
    toTrytes            : ascii.toTrytes,
    fromTrytes          : ascii.fromTrytes,
    extractJson         : extractJson,
    validateSignatures  : validateSignatures,
    isBundle            : isBundle
}


/***/ }),

/***/ "./src/WebGL/index.js":
/*!****************************!*\
  !*** ./src/WebGL/index.js ***!
  \****************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var initGL = __webpack_require__(/*! ./initGL */ "./src/WebGL/initGL.js");
var newBuffer = __webpack_require__(/*! ./newBuffer */ "./src/WebGL/newBuffer.js");
var createTexture = __webpack_require__(/*! ./texture */ "./src/WebGL/texture.js");
var ShaderCode = __webpack_require__(/*! ./shadercode */ "./src/WebGL/shadercode.js");

function _frameBufferSetTexture(gl, fbo, nTexture, dim) {
  gl.bindFramebuffer(gl.FRAMEBUFFER, fbo);
  // Types arrays speed this up tremendously.
  //var nTexture = createTexture(gl, new Int32Array(length), dim);

  gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, nTexture, 0);

  // Test for mobile bug MDN->WebGL_best_practices, bullet 7
  var frameBufferStatus = gl.checkFramebufferStatus(gl.FRAMEBUFFER) == gl.FRAMEBUFFER_COMPLETE;

  if (!frameBufferStatus) throw new Error('turbojs: Error attaching float texture to framebuffer. Your device is probably incompatible. Error info: ' + frameBufferStatus.message);
}
function alloc(sz) {
  // A sane limit for most GPUs out there.
  // JS falls apart before GLSL limits could ever be reached.

  var ns = Math.pow(Math.pow(2, Math.ceil(Math.log(sz) / 1.386) - 1), 2);
  return {
    //data : new Int32Array(ns * 16),
    data: new Int32Array(sz),
    length: sz
  };
}
var _bindBuffers = function _bindBuffers(gl, buffers, attrib) {
  gl.bindBuffer(gl.ARRAY_BUFFER, buffers.texture);
  gl.enableVertexAttribArray(attrib.texture);
  gl.vertexAttribPointer(attrib.texture, 2, gl.FLOAT, false, 0, 0);
  gl.bindBuffer(gl.ARRAY_BUFFER, buffers.position);
  gl.enableVertexAttribArray(attrib.position);
  gl.vertexAttribPointer(attrib.position, 2, gl.FLOAT, false, 0, 0);
  gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, buffers.index);
};
var _createVertexShader = function _createVertexShader(gl) {
  var vertexShader = gl.createShader(gl.VERTEX_SHADER);
  gl.shaderSource(vertexShader, ShaderCode.vertexShaderCode);
  gl.compileShader(vertexShader);

  // This should not fail.
  if (!gl.getShaderParameter(vertexShader, gl.COMPILE_STATUS)) throw new Error("\nturbojs: Could not build internal vertex shader (fatal).\n" + "\n" + "INFO: >REPORT< THIS. That's our fault!\n" + "\n" + "--- CODE DUMP ---\n" + ShaderCode.vertexShaderCode + "\n\n" + "--- ERROR LOG ---\n" + gl.getShaderInfoLog(vertexShader));
  return vertexShader;
};
var _createFragmentShader = function _createFragmentShader(gl, code) {
  var fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);

  gl.shaderSource(fragmentShader, ShaderCode.stdlib + code);

  gl.compileShader(fragmentShader);
  // Use this output to debug the shader
  // Keep in mind that WebGL GLSL is **much** stricter than e.g. OpenGL GLSL
  if (!gl.getShaderParameter(fragmentShader, gl.COMPILE_STATUS)) {
    var LOC = code.split('\n');
    var dbgMsg = "ERROR: Could not build shader (fatal).\n\n------------------ KERNEL CODE DUMP ------------------\n";

    for (var nl = 0; nl < LOC.length; nl++) {
      dbgMsg += ShaderCode.stdlib.split('\n').length + nl + "> " + LOC[nl] + "\n";
    }dbgMsg += "\n--------------------- ERROR  LOG ---------------------\n" + gl.getShaderInfoLog(fragmentShader);

    throw new Error(dbgMsg);
  }
  return fragmentShader;
};
var _finishRun = function _finishRun(gl) {
  gl.bindVertexArray(null);
  gl.bindTexture(gl.TEXTURE_2D, null);
  gl.bindFramebuffer(gl.FRAMEBUFFER, null);
};
var WebGLWorker = function WebGLWorker(l, s) {

  var worker = new Object();
  worker.gl = initGL();
  var gl = worker.gl;

  worker.dim = {
    x: l,
    y: 0
  };
  var MAXIMAGESIZE = Math.pow(gl.MAX_TEXTURE_SIZE, 2) * 0.50;
  var IMAGE_SIZE = Math.floor(MAXIMAGESIZE / worker.dim.x / s) * worker.dim.x * s;
  worker.dim.y = IMAGE_SIZE / worker.dim.x / s;
  var length = IMAGE_SIZE;

  worker.programs = new Map();
  worker.ipt = alloc(length);

  // GPU texture buffer = from JS typed array
  worker.buffers = {
    position: newBuffer(gl, [-1, -1, 1, -1, 1, 1, -1, 1]),
    texture: newBuffer(gl, [0, 0, 1, 0, 1, 1, 0, 1]),
    index: newBuffer(gl, [1, 2, 0, 3, 0, 2], Uint16Array, gl.ELEMENT_ARRAY_BUFFER)
  };

  worker.attrib = {
    position: 0,
    texture: 1
  };

  worker.vao = gl.createVertexArray();
  gl.bindVertexArray(worker.vao);
  _bindBuffers(gl, worker.buffers, worker.attrib);
  gl.bindVertexArray(null);
  worker.vertexShader = _createVertexShader(gl);
  worker.framebuffer = gl.createFramebuffer();
  worker.texture0 = createTexture(gl, worker.ipt.data, worker.dim);
  worker.texture1 = createTexture(gl, new Int32Array(length), worker.dim);
  return worker;
};
module.exports = {
  worker: WebGLWorker,
  addProgram: function addProgram(worker, name, code) {
    for (var _len = arguments.length, uniforms = Array(_len > 3 ? _len - 3 : 0), _key = 3; _key < _len; _key++) {
      uniforms[_key - 3] = arguments[_key];
    }

    var gl = worker.gl;
    var vertexShader = worker.vertexShader;

    var fragmentShader = _createFragmentShader(worker.gl, code);
    var program = gl.createProgram();

    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.bindAttribLocation(program, worker.attrib.position, 'position');
    gl.bindAttribLocation(program, worker.attrib.texture, 'texture');
    gl.linkProgram(program);
    var u_vars = new Map();
    var _iteratorNormalCompletion = true;
    var _didIteratorError = false;
    var _iteratorError = undefined;

    try {
      for (var _iterator = uniforms[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
        var variable = _step.value;

        u_vars.set(variable, gl.getUniformLocation(program, variable));
      }
    } catch (err) {
      _didIteratorError = true;
      _iteratorError = err;
    } finally {
      try {
        if (!_iteratorNormalCompletion && _iterator.return) {
          _iterator.return();
        }
      } finally {
        if (_didIteratorError) {
          throw _iteratorError;
        }
      }
    }

    if (!!worker.programs.get(name)) {
      console.log("program exists");
    }
    worker.programs.set(name, { program: program, u_vars: u_vars });
  },
  /*
  use: (name) => {
  },
  */
  run: function run(worker, name, count) {
    for (var _len2 = arguments.length, uniforms = Array(_len2 > 3 ? _len2 - 3 : 0), _key2 = 3; _key2 < _len2; _key2++) {
      uniforms[_key2 - 3] = arguments[_key2];
    }

    var gl = worker.gl;
    var info = worker.programs.get(name);
    var program = info.program;
    var u_vars = info.u_vars;
    if (program === null) throw new Error("No Such Program!");

    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error('turbojs: Failed to link GLSL program code.');

    var uTexture = gl.getUniformLocation(program, 'u_texture');
    gl.useProgram(program);

    count = count || 1;
    while (count-- > 0) {
      gl.bindTexture(gl.TEXTURE_2D, worker.texture0);
      gl.activeTexture(gl.TEXTURE0);
      gl.uniform1i(uTexture, 0);

      gl.viewport(0, 0, worker.dim.x, worker.dim.y);
      _frameBufferSetTexture(gl, worker.framebuffer, worker.texture1, worker.dim); //new
      gl.bindVertexArray(worker.vao);
      var _iteratorNormalCompletion2 = true;
      var _didIteratorError2 = false;
      var _iteratorError2 = undefined;

      try {
        for (var _iterator2 = uniforms[Symbol.iterator](), _step2; !(_iteratorNormalCompletion2 = (_step2 = _iterator2.next()).done); _iteratorNormalCompletion2 = true) {
          var u_v = _step2.value;

          gl.uniform1i(u_vars.get(u_v.n), u_v.v);
        }
      } catch (err) {
        _didIteratorError2 = true;
        _iteratorError2 = err;
      } finally {
        try {
          if (!_iteratorNormalCompletion2 && _iterator2.return) {
            _iterator2.return();
          }
        } finally {
          if (_didIteratorError2) {
            throw _iteratorError2;
          }
        }
      }

      gl.drawElements(gl.TRIANGLES, 6, gl.UNSIGNED_SHORT, 0);
      var tex0 = worker.texture0;
      worker.texture0 = worker.texture1;
      worker.texture1 = tex0;
    }

    _finishRun(gl);
  },
  readData: function readData(worker, x, y, N, M) {
    var gl = worker.gl;
    x = x || 0;
    y = y || 0;
    N = N || worker.dim.x;
    M = M || worker.dim.y;
    gl.bindFramebuffer(gl.FRAMEBUFFER, worker.framebuffer);
    gl.readPixels(x, y, N, M, gl.RGBA_INTEGER, gl.INT, worker.ipt.data);
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    return worker.ipt.data.subarray(0, worker.ipt.length);
  },
  writeData: function writeData(worker, data) {
    var gl = worker.gl;
    gl.bindTexture(gl.TEXTURE_2D, worker.texture0);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA32I, worker.dim.x, worker.dim.y, 0, gl.RGBA_INTEGER, gl.INT, data);
    gl.bindTexture(gl.TEXTURE_2D, null);
  }
};

/***/ }),

/***/ "./src/WebGL/initGL.js":
/*!*****************************!*\
  !*** ./src/WebGL/initGL.js ***!
  \*****************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = function () {
  var canvas = document.createElement('canvas');
  //var canvas = document.getElementById('c');
  var gl = null;
  var attr = { alpha: false, antialias: false };

  // Try to grab the standard context. If it fails, fallback to experimental.
  gl = canvas.getContext("webgl2", attr) || canvas.getContext("experimental-webgl2", attr);

  // If we don't have a GL context, give up now
  if (!gl) {
    // gl instanceof WebGLRenderingContext)
    throw new Error("Unable to initialize WebGL. Your browser may not support it.");
  }

  return gl;
};

/***/ }),

/***/ "./src/WebGL/newBuffer.js":
/*!********************************!*\
  !*** ./src/WebGL/newBuffer.js ***!
  \********************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = function (gl, data, f, e) {
  var buf = gl.createBuffer();

  gl.bindBuffer(e || gl.ARRAY_BUFFER, buf);
  gl.bufferData(e || gl.ARRAY_BUFFER, new (f || Float32Array)(data), gl.STATIC_DRAW);

  return buf;
};

/***/ }),

/***/ "./src/WebGL/shadercode.js":
/*!*********************************!*\
  !*** ./src/WebGL/shadercode.js ***!
  \*********************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = {
  vertexShaderCode: "#version 300 es\nlayout(location = 0) in vec2 position;\nlayout(location = 1) in vec2 texture;\nout vec2 pos;\n\nvoid main(void) {\n  pos = texture;\n  gl_Position = vec4(position.xy, 0.0, 1.0);\n}",
  stdlib: "#version 300 es\nprecision highp float;\nprecision highp int;\nprecision highp isampler2D;\nuniform isampler2D u_texture;\nin vec2 pos;\nout ivec4 color;\n//out int isFinished;\n\nvec2 size;\nivec2 my_coord;\n\nvoid init(void) {\n  //size = vec2(textureSize(u_texture, 0) - 1);\n  size = vec2(textureSize(u_texture, 0));\n  my_coord = ivec2(pos * size);\n}\n\nivec4 read(void) {\n  return texture(u_texture, pos);\n}\n\nivec4 read_at(ivec2 coord) {\n  return texelFetch(u_texture, coord, 0);\n}\n\nvoid commit(ivec4 val) {\n  color = val;\n}\n" };

/***/ }),

/***/ "./src/WebGL/texture.js":
/*!******************************!*\
  !*** ./src/WebGL/texture.js ***!
  \******************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


// Transfer data onto clamped texture and turn off any filtering
module.exports = function createTexture(gl, data, dim) {
  var texture = gl.createTexture();

  gl.bindTexture(gl.TEXTURE_2D, texture);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
  gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA32I, dim.x, dim.y, 0, gl.RGBA_INTEGER, gl.INT, data);
  //gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA32F, size, size, 0, gl.RGBA, gl.FLOAT, data);
  //gl.texStorage2D(gl.TEXTURE_2D, 1, gl.RGBA32F, size, size);
  gl.bindTexture(gl.TEXTURE_2D, null);

  return texture;
};

/***/ }),

/***/ "./src/constants.js":
/*!**************************!*\
  !*** ./src/constants.js ***!
  \**************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var HASH_LENGTH = 243;
var INT_LENGTH = 27;
var NONCE_LENGTH = HASH_LENGTH / 3;
var TIMESTAMP_START = NONCE_LENGTH;
var TIMESTAMP_LOWER_BOUND_START = TIMESTAMP_START + INT_LENGTH;
var TIMESTAMP_UPPER_BOUND_START = TIMESTAMP_LOWER_BOUND_START + INT_LENGTH;
var NONCE_START = HASH_LENGTH - NONCE_LENGTH;

module.exports = {
  HASH_LENGTH: HASH_LENGTH,
  STATE_LENGTH: HASH_LENGTH * 3,
  TIMESTAMP_START: TIMESTAMP_START,
  TIMESTAMP_LOWER_BOUND_START: TIMESTAMP_LOWER_BOUND_START,
  TIMESTAMP_UPPER_BOUND_START: TIMESTAMP_UPPER_BOUND_START,
  NONCE_START: NONCE_START,
  NONCE_LENGTH: NONCE_LENGTH,
  INT_LENGTH: INT_LENGTH,
  NUMBER_OF_ROUNDS: 81,
  TRANSACTION_LENGTH: HASH_LENGTH * 33
};

/***/ }),

/***/ "./src/curl.js":
/*!*********************!*\
  !*** ./src/curl.js ***!
  \*********************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var Const = __webpack_require__(/*! ./constants */ "./src/constants.js");

/**
 **      Cryptographic related functions to IOTA's Curl (sponge function)
 **/

function Curl(state) {
  // truth table
  this.truthTable = new Int8Array([1, 0, -1, 2, 1, -1, 0, 2, -1, 1, 0]);
  this.HASH_LENGTH = Const.HASH_LENGTH;
  this.initialize(state);
  this.reset();
}

/**
 *   Initializes the state with 729 trits
 *
 *   @method initialize
 **/
Curl.prototype.initialize = function (state, length) {

  if (state) {
    this.state = state;
  } else {
    this.state = new Int8Array(Const.STATE_LENGTH);
  }
};

Curl.prototype.reset = function () {
  this.state.fill(0);
};

/**
 *   Sponge absorb function
 *
 *   @method absorb
 **/
Curl.prototype.absorb = function (trits, offset, length) {

  do {

    var i = 0;
    var limit = length < Const.HASH_LENGTH ? length : Const.HASH_LENGTH;

    while (i < limit) {

      this.state[i++] = trits[offset++];
    }

    this.transform();
  } while ((length -= Const.HASH_LENGTH) > 0);
};

/**
 *   Sponge squeeze function
 *
 *   @method squeeze
 **/
Curl.prototype.squeeze = function (trits, offset, length) {

  do {

    var i = 0;
    var limit = length < Const.HASH_LENGTH ? length : Const.HASH_LENGTH;

    while (i < limit) {

      trits[offset++] = this.state[i++];
    }

    this.transform();
  } while ((length -= Const.HASH_LENGTH) > 0);
};

/**
 *   Sponge transform function
 *
 *   @method transform
 **/
Curl.prototype.transform = function () {

  var stateCopy = [],
      index = 0;

  for (var round = 0; round < Const.NUMBER_OF_ROUNDS; round++) {

    stateCopy = this.state.slice();

    for (var i = 0; i < Const.STATE_LENGTH; i++) {

      this.state[i] = this.truthTable[stateCopy[index] + (stateCopy[index += index < 365 ? 364 : -365] << 2) + 5];
    }
  }
};

module.exports = Curl;

/***/ }),

/***/ "./src/curl.lib.js":
/*!*************************!*\
  !*** ./src/curl.lib.js ***!
  \*************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var PearlDiver = __webpack_require__(/*! ./pearldiver */ "./src/pearldiver.js");
var Curl = __webpack_require__(/*! ./curl */ "./src/curl.js");
var Const = __webpack_require__(/*! ./constants */ "./src/constants.js");
var Converter = __webpack_require__(/*! iota.crypto.js */ "./node_modules/iota.crypto.js/lib/iota.crypto.js").converter;
var NONCE_TIMESTAMP_LOWER_BOUND = 0;
var NONCE_TIMESTAMP_UPPER_BOUND = Converter.fromValue(0xffffffffffffffff);
var MAX_TIMESTAMP_VALUE = (Math.pow(3, 27) - 1) / 2;

var pdInstance = void 0;

var pow = function pow(options, success, error) {
  var state = void 0;

  if ('trytes' in options) {
    state = PearlDiver.prepare(options.trytes);
  } else if ('state' in options) {
    state = PearlDiver.offsetState(options.state);
  } else {
    error("Error: no trytes or state matrix provided");
  }
  var powPromise = PearlDiver.search(pdInstance, state, options.minWeight);
  if (typeof success === 'function') {
    powPromise.then(success).catch(error);
  }
  return powPromise;
};

var TAG_TRINARY_START = 2295;
var TAG_TRINARY_SIZE = 27;

var setTimestamp = function setTimestamp(state) {
  var timestamp = state.subarray(Const.TIMESTAMP_START, Const.TIMESTAMP_LOWER_BOUND_START);
  var upper = state.subarray(Const.TIMESTAMP_UPPER_BOUND_START, Const.NONCE_START);
  timestamp.fill(0);
  Converter.fromValue(Date.now()).map(function (v, i) {
    return timestamp[i] = v;
  });
  state.subarray(Const.TIMESTAMP_LOWER_BOUND_START, Const.TIMESTAMP_UPPER_BOUND_START).fill(0);
  upper.fill(0);
  NONCE_TIMESTAMP_UPPER_BOUND.map(function (v, i) {
    return upper[i] = v;
  });
};

var overrideAttachToTangle = function overrideAttachToTangle(iota) {
  iota.api.attachToTangle = function (trunkTransaction, branchTransaction, minWeight, trytes, callback) {
    var ccurlHashing = function ccurlHashing(trunkTransaction, branchTransaction, minWeight, trytes, callback) {
      var iotaObj = iota;

      // inputValidator: Check if correct hash
      if (!iotaObj.valid.isHash(trunkTransaction)) {
        return callback(new Error("Invalid trunkTransaction"));
      }

      // inputValidator: Check if correct hash
      if (!iotaObj.valid.isHash(branchTransaction)) {
        return callback(new Error("Invalid branchTransaction"));
      }

      // inputValidator: Check if int
      if (!iotaObj.valid.isValue(minWeight)) {
        return callback(new Error("Invalid minWeightMagnitude"));
      }

      var finalBundleTrytes = [];
      var previousTxHash;
      var i = 0;

      function loopTrytes() {
        getBundleTrytes(trytes[i], function (error) {
          if (error) {
            return callback(error);
          } else {
            i++;
            if (i < trytes.length) {
              loopTrytes();
            } else {
              // reverse the order so that it's ascending from currentIndex
              return callback(null, finalBundleTrytes.reverse());
            }
          }
        });
      }

      function getBundleTrytes(thisTrytes, callback) {
        // PROCESS LOGIC:
        // Start with last index transaction
        // Assign it the trunk / branch which the user has supplied
        // IF there is a bundle, chain  the bundle transactions via
        // trunkTransaction together

        var txObject = iotaObj.utils.transactionObject(thisTrytes);
        txObject.tag = txObject.obsoleteTag;
        txObject.attachmentTimestamp = Date.now();
        txObject.attachmentTimestampLowerBound = 0;
        txObject.attachmentTimestampUpperBound = MAX_TIMESTAMP_VALUE;
        // If this is the first transaction, to be processed
        // Make sure that it's the last in the bundle and then
        // assign it the supplied trunk and branch transactions
        if (!previousTxHash) {
          // Check if last transaction in the bundle
          if (txObject.lastIndex !== txObject.currentIndex) {
            return callback(new Error("Wrong bundle order. The bundle should be ordered in descending order from currentIndex"));
          }

          txObject.trunkTransaction = trunkTransaction;
          txObject.branchTransaction = branchTransaction;
        } else {
          // Chain the bundle together via the trunkTransaction (previous tx in the bundle)
          // Assign the supplied trunkTransaciton as branchTransaction
          txObject.trunkTransaction = previousTxHash;
          txObject.branchTransaction = trunkTransaction;
        }

        var newTrytes = iotaObj.utils.transactionTrytes(txObject);

        curl.pow({ trytes: newTrytes, minWeight: minWeight }).then(function (nonce) {
          var returnedTrytes = newTrytes.substr(0, 2673 - 81).concat(nonce);
          var newTxObject = iotaObj.utils.transactionObject(returnedTrytes);

          // Assign the previousTxHash to this tx
          var txHash = newTxObject.hash;
          previousTxHash = txHash;

          finalBundleTrytes.push(returnedTrytes);
          callback(null);
        }).catch(callback);
      }
      loopTrytes();
    };
    ccurlHashing(trunkTransaction, branchTransaction, minWeight, trytes, function (error, success) {
      if (error) {
        console.log(error);
      } else {
        console.log(success);
      }
      if (callback) {
        return callback(error, success);
      } else {
        return success;
      }
    });
  };
};

window.curl = module.exports = {
  init: function init() {
    pdInstance = PearlDiver.instance();
    if (pdInstance == null) {
      return false;
    }
    return true;
  },
  pow: pow,
  prepare: PearlDiver.prepare,
  setOffset: function setOffset(o) {
    pdInstance.offset = o;
  },
  interrupt: function (_interrupt) {
    function interrupt() {
      return _interrupt.apply(this, arguments);
    }

    interrupt.toString = function () {
      return _interrupt.toString();
    };

    return interrupt;
  }(function () {
    return interrupt(pdInstance);
  }),
  resume: function resume() {
    return PearlDiver.doNext(pdInstance);
  },
  remove: function remove() {
    return pdInstance.queue.unshift();
  },
  //getHashRows: (c) => c(PearlDiver.getHashCount()),
  overrideAttachToTangle: overrideAttachToTangle
};

/***/ }),

/***/ "./src/pearldiver.js":
/*!***************************!*\
  !*** ./src/pearldiver.js ***!
  \***************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var Converter = __webpack_require__(/*! iota.crypto.js */ "./node_modules/iota.crypto.js/lib/iota.crypto.js").converter;
var Curl = __webpack_require__(/*! ./curl */ "./src/curl.js");
var WebGL = __webpack_require__(/*! ./WebGL */ "./src/WebGL/index.js");
var SearchInit = __webpack_require__(/*! ./searchInit */ "./src/searchInit.js");
var KRNL = __webpack_require__(/*! ./shaders */ "./src/shaders/index.js");
var Const = __webpack_require__(/*! ./constants */ "./src/constants.js");

var TEXELSIZE = 4;

var PDState = {
  READY: 0,
  SEARCHING: 1,
  INTERRUPTED: -1
};

var pack = function pack(l) {
  return function (r, k, i) {
    return (i % l === 0 ? r.push([k]) : r[r.length - 1].push(k)) && r;
  };
};

var pearlDiverCallback = function pearlDiverCallback(res, transactionTrits, minWeightMagnitude, m_self) {
  return function (nonce, searchObject) {
    res(Converter.trytes(nonce));
  };
};

var PearlDiverInstance = function PearlDiverInstance(offset) {
  if (WebGL) {
    var instance = new Object();
    instance.context = WebGL.worker(Const.STATE_LENGTH + 1, TEXELSIZE);
    instance.offset = instance.context.dim.y * (offset || 0);
    instance.buf = instance.context.ipt.data;
    WebGL.addProgram(instance.context, "init", KRNL.init, "gr_offset");
    WebGL.addProgram(instance.context, "increment", KRNL.increment);
    WebGL.addProgram(instance.context, "twist", KRNL.transform);
    WebGL.addProgram(instance.context, "check", KRNL.check, "minWeightMagnitude");
    WebGL.addProgram(instance.context, "col_check", KRNL.col_check);
    WebGL.addProgram(instance.context, "finalize", KRNL.finalize);
    instance.state = PDState.READY;
    instance.queue = [];
    return instance;
  }
};

var search = function search(instance, states, minWeight) {
  if (!instance.context) {
    Promise.reject(new Error("Webgl2 Is not Available"));
  } else if (minWeight >= Const.HASH_LENGTH || minWeight <= 0) {
    Promise.reject(new Error("Bad Min-Weight Magnitude"));
  }
  return new Promise(function (res, rej) {
    instance.queue.push({
      states: states,
      mwm: minWeight,
      call: pearlDiverCallback(res, states, minWeight, instance)
    });
    if (instance.state == PDState.READY) doNext(instance);
  });
};

var interrupt = function interrupt(instance) {
  if (instance.state == PDState.SEARCHING) instance.state = PDState.INTERRUPTED;
};

var doNext = function doNext(instance) {
  var next = instance.queue.shift();
  if (instance.state != PDState.SEARCHING) {
    if (next != null) {
      instance.state = PDState.SEARCHING;
      _WebGLFindNonce(instance, next);
    }
  } else {
    instance.state = PDState.READY;
  }
};

var _save = function _save(instance, searchObject) {
  instance.buf.reduce(pack(4), []).slice(0, Const.STATE_LENGTH).reduce(function (a, v) {
    return a.map(function (c, i) {
      return c.push(v[i]);
    }) && a;
  }, [[], []]).reduce(function (a, v, i) {
    return (i % 2 ? a.set("high", v) : a.set("low", v)) && a;
  }, new Map()).forEach(function (v, k) {
    return searchObject.states[k] = v;
  });
  instance.queue.unshift(searchObject);
};

var _WebGLWriteBuffers = function _WebGLWriteBuffers(instance, states) {
  for (var i = 0; i < Const.STATE_LENGTH; i++) {
    instance.buf[i * TEXELSIZE] = states.low[i];
    instance.buf[i * TEXELSIZE + 1] = states.high[i];
    instance.buf[i * TEXELSIZE + 2] = states.low[i];
    instance.buf[i * TEXELSIZE + 3] = states.high[i];
  }
};

var _WebGLSearch = function _WebGLSearch(instance, searchObject) {
  WebGL.run(instance.context, "increment");
  WebGL.run(instance.context, "twist", Const.NUMBER_OF_ROUNDS);
  WebGL.run(instance.context, "check", 1, { n: "minWeightMagnitude", v: searchObject.mwm });
  WebGL.run(instance.context, "col_check");

  if (WebGL.readData(instance.context, Const.STATE_LENGTH, 0, 1, 1)[2] === -1) {
    if (instance.state == PDState.INTERRUPTED) return instance._save(searchObject);
    //requestAnimationFrame(() => instance._WebGLSearch(searchObject));
    setTimeout(function () {
      return _WebGLSearch(instance, searchObject);
    }, 1);
  } else {
    WebGL.run(instance.context, "finalize");
    searchObject.call(WebGL.readData(instance.context, 0, 0, instance.context.dim.x, 1).reduce(pack(4), []).slice(0, Const.HASH_LENGTH).map(function (x) {
      return x[3];
    }), searchObject);
    doNext(instance);
  }
};

var _WebGLFindNonce = function _WebGLFindNonce(instance, searchObject) {
  _WebGLWriteBuffers(instance, searchObject.states);
  WebGL.writeData(instance.context, instance.buf);
  WebGL.run(instance.context, "init", 1, { n: "gr_offset", v: instance.offset });
  //requestAnimationFrame(() => instance._WebGLSearch(searchObject));
  setTimeout(function () {
    return _WebGLSearch(instance, searchObject);
  }, 1);
};
var searchWithCallback = function searchWithCallback(instance, transactionTrytes, minWeightMagnitude, callback, err) {
  if (transactionTrits.length < Const.TRANSACTION_LENGTH - Const.HASH_LENGTH) return null;
  var curl = new Curl();
  var transactionTrits = Converter.trits(transactionTrytes);
  curl.absorb(transactionTrits, 0, Const.TRANSACTION_LENGTH - Const.HASH_LENGTH);
  var states = SearchInit.toPair(curl.state, minWeightMagnitude);
  search(instance, states, minWeightMagnitude).then(callback).catch(err);
};
var offsetState = function offsetState(state) {
  return SearchInit.toPair(Converter.trits(state));
};
var prepare = function prepare(transactionTrytes, minWeightMagnitude) {
  var curl = new Curl();
  var transactionTrits = Converter.trits(transactionTrytes);
  curl.absorb(transactionTrits, 0, Const.TRANSACTION_LENGTH - Const.HASH_LENGTH);
  transactionTrits.slice(Const.TRANSACTION_LENGTH - Const.HASH_LENGTH, Const.TRANSACTION_LENGTH).forEach(function (v, i) {
    curl.state[i] = v;
  });
  var states = SearchInit.toPair(curl.state);
  return states;
};

module.exports = {
  instance: PearlDiverInstance,
  offsetState: offsetState,
  prepare: prepare,
  search: search,
  doNext: doNext
};

/***/ }),

/***/ "./src/searchInit.js":
/*!***************************!*\
  !*** ./src/searchInit.js ***!
  \***************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var Const = __webpack_require__(/*! ./constants */ "./src/constants.js");
var TRYTE_LENGTH = 2673,
    TRANSACTION_LENGTH = TRYTE_LENGTH * 3,
    LOW_BITS = 0,
    //00000000,
HIGH_BITS = -1,
    //0xFFFFFFFF,//FFFFFFFF,4294967295, 
LOW_0 = 0xDB6DB6DB,
    //6DB6DB6D,
LOW_1 = 0xF1F8FC7E,
    //3F1F8FC7,
LOW_2 = 0x7FFFE00F,
    //FFFC01FF,
LOW_3 = 0xFFC00000,
    //07FFFFFF,
HIGH_0 = 0xB6DB6DB6,
    //DB6DB6DB,
HIGH_1 = 0x8FC7E3F1,
    //F8FC7E3F,
HIGH_2 = 0xFFC01FFF,
    //F803FFFF,
HIGH_3 = 0x003FFFFF; //FFFFFFFF,
/*
  HIGH_BITS= 0xFFFFFFFFFFFFFFFF,
  LOW_BITS= 0x0000000000000000,
  LOW_0= 0xDB6DB6DB6DB6DB6D,
  HIGH_0= 0xB6DB6DB6DB6DB6DB,
  LOW_1= 0xF1F8FC7E3F1F8FC7,
  HIGH_1= 0x8FC7E3F1F8FC7E3F,
  LOW_2= 0x7FFFE00FFFFC01FF,
  HIGH_2= 0xFFC01FFFF803FFFF,
  LOW_3= 0xFFC0000007FFFFFF,
  HIGH_3= 0x003FFFFFFFFFFFFF;
  */

function offset(states, offset) {
  states.low[offset + 0] = LOW_0;
  states.low[offset + 1] = LOW_1;
  states.low[offset + 2] = LOW_2;
  states.low[offset + 3] = LOW_3;
  states.high[offset + 0] = HIGH_0;
  states.high[offset + 1] = HIGH_1;
  states.high[offset + 2] = HIGH_2;
  states.high[offset + 3] = HIGH_3;
}

function toPair(state) {
  var states = {
    low: new Int32Array(Const.STATE_LENGTH),
    high: new Int32Array(Const.STATE_LENGTH)
  };
  state.forEach(function (trit, i) {
    switch (trit) {
      case 0:
        {
          states.low[i] = HIGH_BITS;
          states.high[i] = HIGH_BITS;
        }break;
      case 1:
        {
          states.low[i] = LOW_BITS;
          states.high[i] = HIGH_BITS;
        }break;
      default:
        {
          states.low[i] = HIGH_BITS;
          states.high[i] = LOW_BITS;
        }
    }
  });
  offset(states, Const.NONCE_START);
  return states;
}

function transform(states) {
  var scratchpadHigh, scratchpadLow;
  var scratchpadIndex = 0,
      round,
      stateIndex;
  var alpha, beta, gamma, delta;

  for (round = Const.NUMBER_OF_ROUNDS; round-- > 0;) {
    scratchpadLow = states.low.slice();
    scratchpadHigh = states.high.slice();

    for (stateIndex = 0; stateIndex < Const.STATE_LENGTH; stateIndex++) {
      alpha = scratchpadLow[scratchpadIndex];
      beta = scratchpadHigh[scratchpadIndex];
      gamma = scratchpadHigh[scratchpadIndex += scratchpadIndex < 365 ? 364 : -365];
      delta = (alpha | ~gamma) & (scratchpadLow[scratchpadIndex] ^ beta);

      states.low[stateIndex] = ~delta;
      states.high[stateIndex] = alpha ^ gamma | delta;
    }
  }
}

module.exports = { toPair: toPair, transform: transform };
/*
export default function (states, transactionTrits) {
  var i, offset = 0;
  var j;
  //for (i = HASH_LENGTH; i < STATE_LENGTH; i++) {
  for (i = 0; i < Const.STATE_LENGTH; i++) {
    if (i >= Const.HASH_LENGTH && i < Const.STATE_LENGTH) {
      states.low[i] = HIGH_BITS;
      states.high[i] = HIGH_BITS;
    } else {
      states.low[i] = 0;
      states.high[i] = 0;
    }
  }

  for (i = (Const.TRANSACTION_LENGTH - Const.HASH_LENGTH) / Const.HASH_LENGTH; i-- > 0; ) {

    for (j = 0; j < Const.HASH_LENGTH; j++) {
      switch (transactionTrits[offset++]) {
        case 0: {
          states.low[j] = HIGH_BITS;
          states.high[j] = HIGH_BITS;
        } break;
        case 1: {
          states.low[j] = LOW_BITS;
          states.high[j] = HIGH_BITS;
        } break;
        default: {
          states.low[j] = HIGH_BITS;
          states.high[j] = LOW_BITS;
        }
      }
    }
    transform(states);
  }
  states.low[0] = LOW_0;   //0b1101101101101101101101101101101101101101101101101101101101101101L; 
  states.high[0] = HIGH_0; //0b1011011011011011011011011011011011011011011011011011011011011011L;
  states.low[1] = LOW_1;   //0b1111000111111000111111000111111000111111000111111000111111000111L; 
  states.high[1] = HIGH_1; //0b1000111111000111111000111111000111111000111111000111111000111111L;
  states.low[2] = LOW_2;   //0b0111111111111111111000000000111111111111111111000000000111111111L; 
  states.high[2] = HIGH_2; //0b1111111111000000000111111111111111111000000000111111111111111111L;
  states.low[3] = LOW_3;   //0b1111111111000000000000000000000000000111111111111111111111111111L; 
  states.high[3] = HIGH_3; //0b0000000000111111111111111111111111111111111111111111111111111111L;
}
*/

/***/ }),

/***/ "./src/shaders/add.js":
/*!****************************!*\
  !*** ./src/shaders/add.js ***!
  \****************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = "\nint sum (int a, int b) {\n  int my_sum = a + b;\n  return my_sum == 2 ? -1 : (my_sum == -2) ? 1 : my_sum;\n}\nint cons (int a, int b) {\n  return (a == 1 && b == 1)? 1 : (a == -1 && b == -1) ? -1 : 0;\n}\nint any_t (int a, int b) {\n  int my_any = a + b;\n  return my_any == 0 ? 0 : (my_any > 0) ? 1 : -1;\n}\nivec2 full_adder(int a, int b, int c) {\n  int c_a, c_b, sum_ab, c_s;\n\n  c_a    = cons(a,b);\n  sum_ab = sum(a,b);\n  c_b    = cons(sum_ab,c);\n  c_s    = any_t(c_a, c_b);\n\n  return ivec2(sum(sum_ab, c), c_s);\n}\nivec2 get_sum_to_index(int from, int to, int number_to_add, int row) {\n  int trit_to_add, trit_at_index, pow, carry, num_carry;\n  ivec2 read_in, sum_out, out_trit;\n  pow = 1;\n  carry = 0;\n  num_carry = 0;\n\n  for(int i = from; i < to; i++) {\n    //if(trit_to_add == 0 && sum_out.t == 0) continue;\n\n    read_in = read_at ( ivec2 (i, row)).rg;\n\n    trit_to_add = ((number_to_add / pow) % 3) + num_carry;\n    num_carry = trit_to_add > 1 ? 1 : 0;\n    trit_to_add = (trit_to_add == 2 ? -1 : (trit_to_add == 3 ? 0 : trit_to_add));\n\n    sum_out = full_adder(\n      (read_in.s == LOW_BITS ? 1 : read_in.t == LOW_BITS? -1 : 0), \n      trit_to_add, \n      carry\n    );\n\n    if(my_coord.x == i) break;\n    carry = sum_out.t;\n    pow *=3;\n  }\n  if(sum_out.s == 0) {\n    return ivec2(HIGH_BITS);\n  } else if (sum_out.s == 1) {\n    return ivec2(LOW_BITS, HIGH_BITS);\n  } else {\n    return ivec2(HIGH_BITS, LOW_BITS);\n  }\n}\n";

/***/ }),

/***/ "./src/shaders/barrier.js":
/*!********************************!*\
  !*** ./src/shaders/barrier.js ***!
  \********************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = "\n// Choose high != 0 if you want to barrier rg values, 0 if you want to barrier ba\n#define WAITNUM 2\nvoid barrier(ivec2 watch_coords, int high) {\n  ivec4 my_vec = read();\n  if(watch_coords == my_coord) {\n    int hold_index = 0;\n    ivec4 hold_texel;\n    my_vec.g = my_vec.a + 1;\n    my_vec.b = my_vec.g + 1;\n    commit(my_vec);\n    while(hold_index < STATE_LENGTH) {\n      hold_texel = read_at(ivec2(hold_index, my_coord.y));\n      if((high == 0 && hold_texel.r == WAITNUM) ||(high != 0 && hold_texel.a == WAITNUM))\n        hold_index++;\n    }\n    my_vec.a = my_vec.g;\n    //my_vec.a = 123;\n  } else {\n    ivec4 watch = read_at(watch_coords); // r: val to watch, g: expected val, b: next val (should be 1+ expected val)\n    int hold = high == 0 ? my_vec.r : my_vec.a;\n    if(high == 0)\n      my_vec.r = WAITNUM;\n    else\n      my_vec.a = WAITNUM;\n    commit(my_vec);\n    while(watch.g == watch.b || watch.a != watch.g) {\n      //while(watch.g == watch.b || watch.a != 123) {\n      watch = read_at(watch_coords);\n    }\n  }\n  commit(my_vec);\n}\n";

/***/ }),

/***/ "./src/shaders/check.js":
/*!******************************!*\
  !*** ./src/shaders/check.js ***!
  \******************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = { do_check: "\nint check(int row, int min_weight_magnitude) {\n  int nonce_probe, i;\n  ivec2 r_texel;\n  nonce_probe = HIGH_BITS;\n  for(i = min_weight_magnitude; i-- > 0; ) {\n    r_texel = read_at(ivec2(HASH_LENGTH - 1 - i, row)).ba;\n    nonce_probe &= ~(r_texel.s ^ r_texel.t);\n    if(nonce_probe == 0) break;\n  }\n  return nonce_probe;\n}\n", k_check: "\nuniform int minWeightMagnitude;\nvoid main() {\n  init();\n  ivec4 my_vec = read();\n  if(my_coord.x == STATE_LENGTH) {\n    my_vec.r = minWeightMagnitude;\n    my_vec.a = check(my_coord.y, minWeightMagnitude);\n  }\n  commit(my_vec);\n}\n", col: "\nvoid main() {\n  init();\n  ivec4 my_vec = read();\n  int i;\n  if(my_coord.x == STATE_LENGTH && my_coord.y == 0) {\n    my_vec.b = 0;\n    if(my_vec.a == 0) {\n      ivec4 read_vec;\n      my_vec.b = -1;\n      for(i = 1; i < int(size.y); i++) {\n        read_vec = read_at( ivec2( STATE_LENGTH, i));\n        if(read_vec.a != 0) {\n          my_vec.a = read_vec.a;\n          my_vec.b = i;\n          break;\n        }\n      }\n    }\n  }\n  commit(my_vec);\n}\n"
};

/***/ }),

/***/ "./src/shaders/finalize.js":
/*!*********************************!*\
  !*** ./src/shaders/finalize.js ***!
  \*********************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = "\nvoid main() {\n  init();\n  ivec4 my_vec = read();\n  if(my_coord.y == 0 && my_coord.x == STATE_LENGTH) {\n    my_vec.g = check(my_vec.b, my_vec.r);\n  }\n  if(my_coord.y == 0 && my_coord.x < HASH_LENGTH) {\n    ivec4 info_vec = read_at(ivec2(STATE_LENGTH, 0));\n    int nonce_probe = info_vec.a;\n    int row = info_vec.b;\n    ivec4 hash_vec = read_at(ivec2(my_coord.x, row));\n    my_vec.a = (hash_vec.r & nonce_probe) == 0? 1 : ((hash_vec.g & nonce_probe) == 0? -1 : 0);\n  }\n  commit(my_vec);\n}\n";

/***/ }),

/***/ "./src/shaders/headers.js":
/*!********************************!*\
  !*** ./src/shaders/headers.js ***!
  \********************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = "#define HASH_LENGTH 243\n#define NUMBER_OF_ROUNDS 81\n#define INCREMENT_START HASH_LENGTH - 64\n#define STATE_LENGTH 3 * HASH_LENGTH\n#define HALF_LENGTH 364\n#define HIGH_BITS 0xFFFFFFFF\n#define LOW_BITS 0x00000000\n";

/***/ }),

/***/ "./src/shaders/increment.js":
/*!**********************************!*\
  !*** ./src/shaders/increment.js ***!
  \**********************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = "\nvoid main() {\n  init();\n  ivec4 my_vec = read();\n  if(my_coord.x >= INCREMENT_START && my_coord.x < HASH_LENGTH ) {\n    my_vec.rg = get_sum_to_index(INCREMENT_START, HASH_LENGTH, 1, my_coord.y);\n  }\n  if(my_coord.x == STATE_LENGTH ) {\n    my_vec.rg = ivec2(0);\n  }\n  my_vec.ba = my_vec.rg;\n  commit(my_vec);\n}\n";

/***/ }),

/***/ "./src/shaders/index.js":
/*!******************************!*\
  !*** ./src/shaders/index.js ***!
  \******************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var headers = __webpack_require__(/*! ./headers */ "./src/shaders/headers.js");
var finalize = __webpack_require__(/*! ./finalize */ "./src/shaders/finalize.js");
var barrier = __webpack_require__(/*! ./barrier */ "./src/shaders/barrier.js");
var twist = __webpack_require__(/*! ./transform */ "./src/shaders/transform.js");
var check = __webpack_require__(/*! ./check */ "./src/shaders/check.js");
var add = __webpack_require__(/*! ./add */ "./src/shaders/add.js");
var init = __webpack_require__(/*! ./init */ "./src/shaders/init.js");
var increment = __webpack_require__(/*! ./increment */ "./src/shaders/increment.js");

module.exports = {
  init: headers + add + init,
  increment: headers + add + increment,
  transform: headers + twist,
  col_check: headers + check.col,
  check: headers + check.do_check + check.k_check,
  finalize: headers + check.do_check + finalize
};

/***/ }),

/***/ "./src/shaders/init.js":
/*!*****************************!*\
  !*** ./src/shaders/init.js ***!
  \*****************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var k_init = "\nvoid main() {\n  init();\n  commit(offset());\n}\n";
var offset = "\nuniform int gr_offset;\nivec4 offset() {\n  if(my_coord.x >= HASH_LENGTH / 3 && my_coord.x < HASH_LENGTH / 3 * 2 ) {\n    ivec4 my_vec;\n    my_vec.rg = get_sum_to_index(HASH_LENGTH / 3, HASH_LENGTH / 3 * 2, my_coord.y + gr_offset, 0);\n    return my_vec;\n  } else {\n    return read_at(ivec2(my_coord.x,0));\n  }\n}\n";
module.exports = offset + k_init;

/***/ }),

/***/ "./src/shaders/transform.js":
/*!**********************************!*\
  !*** ./src/shaders/transform.js ***!
  \**********************************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var twist = "\nivec2 twist() {\n  int alpha, beta, gamma, delta;\n  ivec4 v1, v2;\n  int j = my_coord.x;\n\n  v1 = read_at(ivec2(j == 0? 0:(((j - 1)%2)+1)*HALF_LENGTH - ((j-1)>>1), my_coord.y));\n  v2 = read_at(ivec2(((j%2)+1)*HALF_LENGTH - ((j)>>1), my_coord.y));\n  alpha = v1.b;\n  beta = v1.a;\n  gamma = v2.a;\n  delta = (alpha | (~gamma)) & (v2.b ^ beta);//v2.b === state_low[t2]\n\n  return ivec2(~delta, (alpha ^ gamma) | delta);\n}\n";
var twistMain = "\nvoid main() {\n  init();\n  ivec4 my_vec = read();\n  if(my_coord.x < STATE_LENGTH)\n    my_vec.ba = twist();\n  commit(my_vec);\n}\n";

var k_transform = "\nvoid transform() {\n  ivec2 scratchpad;\n  ivec4 state = read();\n  int round;\n  for(round = 0; round < NUMBER_OF_ROUNDS; round++) {\n    scratchpad = twist();\n    //barrier(ivec2(STATE_LENGTH,my_coord.y), 0);\n    state.b = scratchpad.s;//sp_low[i];\n    state.a = scratchpad.t;//sp_high[i];\n    commit(state);\n    //barrier(ivec2(STATE_LENGTH,my_coord.y), 0);\n  }\n}\n";

module.exports = twist + twistMain;

/***/ })

/******/ });
});
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly8vd2VicGFjay91bml2ZXJzYWxNb2R1bGVEZWZpbml0aW9uIiwid2VicGFjazovLy93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL2Flcy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL2NpcGhlci1jb3JlLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvY29yZS5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL2VuYy1iYXNlNjQuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9lbmMtdXRmMTYuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9ldnBrZGYuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9mb3JtYXQtaGV4LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvaG1hYy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL2luZGV4LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvbGliLXR5cGVkYXJyYXlzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvbWQ1LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvbW9kZS1jZmIuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9tb2RlLWN0ci1nbGFkbWFuLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvbW9kZS1jdHIuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9tb2RlLWVjYi5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL21vZGUtb2ZiLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvcGFkLWFuc2l4OTIzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvcGFkLWlzbzEwMTI2LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvcGFkLWlzbzk3OTcxLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvcGFkLW5vcGFkZGluZy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3BhZC16ZXJvcGFkZGluZy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3Bia2RmMi5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3JhYmJpdC1sZWdhY3kuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9yYWJiaXQuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9yYzQuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9yaXBlbWQxNjAuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9zaGExLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvc2hhMjI0LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvc2hhMjU2LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvc2hhMy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3NoYTM4NC5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3NoYTUxMi5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3RyaXBsZWRlcy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3g2NC1jb3JlLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvY3J5cHRvL2J1bmRsZS9idW5kbGUuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9jcnlwdG8vY29udmVydGVyL2NvbnZlcnRlci5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvaW90YS5jcnlwdG8uanMvbGliL2NyeXB0by9jb252ZXJ0ZXIvd29yZHMuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9jcnlwdG8vY3VybC9jdXJsLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvY3J5cHRvL2hlbHBlcnMvYWRkZXIuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9jcnlwdG8vaG1hYy9obWFjLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvY3J5cHRvL2tlcmwva2VybC5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvaW90YS5jcnlwdG8uanMvbGliL2NyeXB0by9zaWduaW5nL29sZFNpZ25pbmcuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9jcnlwdG8vc2lnbmluZy9zaWduaW5nLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvZXJyb3JzL2lucHV0RXJyb3JzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvaW90YS5jcnlwdG8uanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9tdWx0aXNpZy9hZGRyZXNzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvbXVsdGlzaWcvbXVsdGlzaWcuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi91dGlscy9hc2NpaVRvVHJ5dGVzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvdXRpbHMvZXh0cmFjdEpzb24uanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi91dGlscy9pbnB1dFZhbGlkYXRvci5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvaW90YS5jcnlwdG8uanMvbGliL3V0aWxzL3V0aWxzLmpzIiwid2VicGFjazovLy8uL3NyYy9XZWJHTC9pbmRleC5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvV2ViR0wvaW5pdEdMLmpzIiwid2VicGFjazovLy8uL3NyYy9XZWJHTC9uZXdCdWZmZXIuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL1dlYkdML3NoYWRlcmNvZGUuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL1dlYkdML3RleHR1cmUuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL2NvbnN0YW50cy5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvY3VybC5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvY3VybC5saWIuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3BlYXJsZGl2ZXIuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NlYXJjaEluaXQuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvYWRkLmpzIiwid2VicGFjazovLy8uL3NyYy9zaGFkZXJzL2JhcnJpZXIuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvY2hlY2suanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvZmluYWxpemUuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvaGVhZGVycy5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvc2hhZGVycy9pbmNyZW1lbnQuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvaW5kZXguanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvaW5pdC5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvc2hhZGVycy90cmFuc2Zvcm0uanMiXSwibmFtZXMiOlsiaW5pdEdMIiwicmVxdWlyZSIsIm5ld0J1ZmZlciIsImNyZWF0ZVRleHR1cmUiLCJTaGFkZXJDb2RlIiwiX2ZyYW1lQnVmZmVyU2V0VGV4dHVyZSIsImdsIiwiZmJvIiwiblRleHR1cmUiLCJkaW0iLCJiaW5kRnJhbWVidWZmZXIiLCJGUkFNRUJVRkZFUiIsImZyYW1lYnVmZmVyVGV4dHVyZTJEIiwiQ09MT1JfQVRUQUNITUVOVDAiLCJURVhUVVJFXzJEIiwiZnJhbWVCdWZmZXJTdGF0dXMiLCJjaGVja0ZyYW1lYnVmZmVyU3RhdHVzIiwiRlJBTUVCVUZGRVJfQ09NUExFVEUiLCJFcnJvciIsIm1lc3NhZ2UiLCJhbGxvYyIsInN6IiwibnMiLCJNYXRoIiwicG93IiwiY2VpbCIsImxvZyIsImRhdGEiLCJJbnQzMkFycmF5IiwibGVuZ3RoIiwiX2JpbmRCdWZmZXJzIiwiYnVmZmVycyIsImF0dHJpYiIsImJpbmRCdWZmZXIiLCJBUlJBWV9CVUZGRVIiLCJ0ZXh0dXJlIiwiZW5hYmxlVmVydGV4QXR0cmliQXJyYXkiLCJ2ZXJ0ZXhBdHRyaWJQb2ludGVyIiwiRkxPQVQiLCJwb3NpdGlvbiIsIkVMRU1FTlRfQVJSQVlfQlVGRkVSIiwiaW5kZXgiLCJfY3JlYXRlVmVydGV4U2hhZGVyIiwidmVydGV4U2hhZGVyIiwiY3JlYXRlU2hhZGVyIiwiVkVSVEVYX1NIQURFUiIsInNoYWRlclNvdXJjZSIsInZlcnRleFNoYWRlckNvZGUiLCJjb21waWxlU2hhZGVyIiwiZ2V0U2hhZGVyUGFyYW1ldGVyIiwiQ09NUElMRV9TVEFUVVMiLCJnZXRTaGFkZXJJbmZvTG9nIiwiX2NyZWF0ZUZyYWdtZW50U2hhZGVyIiwiY29kZSIsImZyYWdtZW50U2hhZGVyIiwiRlJBR01FTlRfU0hBREVSIiwic3RkbGliIiwiTE9DIiwic3BsaXQiLCJkYmdNc2ciLCJubCIsIl9maW5pc2hSdW4iLCJiaW5kVmVydGV4QXJyYXkiLCJiaW5kVGV4dHVyZSIsIldlYkdMV29ya2VyIiwibCIsInMiLCJ3b3JrZXIiLCJPYmplY3QiLCJ4IiwieSIsIk1BWElNQUdFU0laRSIsIk1BWF9URVhUVVJFX1NJWkUiLCJJTUFHRV9TSVpFIiwiZmxvb3IiLCJwcm9ncmFtcyIsIk1hcCIsImlwdCIsIlVpbnQxNkFycmF5IiwidmFvIiwiY3JlYXRlVmVydGV4QXJyYXkiLCJmcmFtZWJ1ZmZlciIsImNyZWF0ZUZyYW1lYnVmZmVyIiwidGV4dHVyZTAiLCJ0ZXh0dXJlMSIsIm1vZHVsZSIsImV4cG9ydHMiLCJhZGRQcm9ncmFtIiwibmFtZSIsInVuaWZvcm1zIiwicHJvZ3JhbSIsImNyZWF0ZVByb2dyYW0iLCJhdHRhY2hTaGFkZXIiLCJiaW5kQXR0cmliTG9jYXRpb24iLCJsaW5rUHJvZ3JhbSIsInVfdmFycyIsInZhcmlhYmxlIiwic2V0IiwiZ2V0VW5pZm9ybUxvY2F0aW9uIiwiZ2V0IiwiY29uc29sZSIsInJ1biIsImNvdW50IiwiaW5mbyIsImdldFByb2dyYW1QYXJhbWV0ZXIiLCJMSU5LX1NUQVRVUyIsInVUZXh0dXJlIiwidXNlUHJvZ3JhbSIsImFjdGl2ZVRleHR1cmUiLCJURVhUVVJFMCIsInVuaWZvcm0xaSIsInZpZXdwb3J0IiwidV92IiwibiIsInYiLCJkcmF3RWxlbWVudHMiLCJUUklBTkdMRVMiLCJVTlNJR05FRF9TSE9SVCIsInRleDAiLCJyZWFkRGF0YSIsIk4iLCJNIiwicmVhZFBpeGVscyIsIlJHQkFfSU5URUdFUiIsIklOVCIsInN1YmFycmF5Iiwid3JpdGVEYXRhIiwidGV4SW1hZ2UyRCIsIlJHQkEzMkkiLCJjYW52YXMiLCJkb2N1bWVudCIsImNyZWF0ZUVsZW1lbnQiLCJhdHRyIiwiYWxwaGEiLCJhbnRpYWxpYXMiLCJnZXRDb250ZXh0IiwiZiIsImUiLCJidWYiLCJjcmVhdGVCdWZmZXIiLCJidWZmZXJEYXRhIiwiRmxvYXQzMkFycmF5IiwiU1RBVElDX0RSQVciLCJ0ZXhQYXJhbWV0ZXJpIiwiVEVYVFVSRV9XUkFQX1MiLCJDTEFNUF9UT19FREdFIiwiVEVYVFVSRV9XUkFQX1QiLCJURVhUVVJFX01JTl9GSUxURVIiLCJORUFSRVNUIiwiVEVYVFVSRV9NQUdfRklMVEVSIiwiSEFTSF9MRU5HVEgiLCJJTlRfTEVOR1RIIiwiTk9OQ0VfTEVOR1RIIiwiVElNRVNUQU1QX1NUQVJUIiwiVElNRVNUQU1QX0xPV0VSX0JPVU5EX1NUQVJUIiwiVElNRVNUQU1QX1VQUEVSX0JPVU5EX1NUQVJUIiwiTk9OQ0VfU1RBUlQiLCJTVEFURV9MRU5HVEgiLCJOVU1CRVJfT0ZfUk9VTkRTIiwiVFJBTlNBQ1RJT05fTEVOR1RIIiwiQ29uc3QiLCJDdXJsIiwic3RhdGUiLCJ0cnV0aFRhYmxlIiwiSW50OEFycmF5IiwiaW5pdGlhbGl6ZSIsInJlc2V0IiwicHJvdG90eXBlIiwiZmlsbCIsImFic29yYiIsInRyaXRzIiwib2Zmc2V0IiwiaSIsImxpbWl0IiwidHJhbnNmb3JtIiwic3F1ZWV6ZSIsInN0YXRlQ29weSIsInJvdW5kIiwic2xpY2UiLCJQZWFybERpdmVyIiwiQ29udmVydGVyIiwiY29udmVydGVyIiwiTk9OQ0VfVElNRVNUQU1QX0xPV0VSX0JPVU5EIiwiTk9OQ0VfVElNRVNUQU1QX1VQUEVSX0JPVU5EIiwiZnJvbVZhbHVlIiwiTUFYX1RJTUVTVEFNUF9WQUxVRSIsInBkSW5zdGFuY2UiLCJvcHRpb25zIiwic3VjY2VzcyIsImVycm9yIiwicHJlcGFyZSIsInRyeXRlcyIsIm9mZnNldFN0YXRlIiwicG93UHJvbWlzZSIsInNlYXJjaCIsIm1pbldlaWdodCIsInRoZW4iLCJjYXRjaCIsIlRBR19UUklOQVJZX1NUQVJUIiwiVEFHX1RSSU5BUllfU0laRSIsInNldFRpbWVzdGFtcCIsInRpbWVzdGFtcCIsInVwcGVyIiwiRGF0ZSIsIm5vdyIsIm1hcCIsIm92ZXJyaWRlQXR0YWNoVG9UYW5nbGUiLCJpb3RhIiwiYXBpIiwiYXR0YWNoVG9UYW5nbGUiLCJ0cnVua1RyYW5zYWN0aW9uIiwiYnJhbmNoVHJhbnNhY3Rpb24iLCJjYWxsYmFjayIsImNjdXJsSGFzaGluZyIsImlvdGFPYmoiLCJ2YWxpZCIsImlzSGFzaCIsImlzVmFsdWUiLCJmaW5hbEJ1bmRsZVRyeXRlcyIsInByZXZpb3VzVHhIYXNoIiwibG9vcFRyeXRlcyIsImdldEJ1bmRsZVRyeXRlcyIsInJldmVyc2UiLCJ0aGlzVHJ5dGVzIiwidHhPYmplY3QiLCJ1dGlscyIsInRyYW5zYWN0aW9uT2JqZWN0IiwidGFnIiwib2Jzb2xldGVUYWciLCJhdHRhY2htZW50VGltZXN0YW1wIiwiYXR0YWNobWVudFRpbWVzdGFtcExvd2VyQm91bmQiLCJhdHRhY2htZW50VGltZXN0YW1wVXBwZXJCb3VuZCIsImxhc3RJbmRleCIsImN1cnJlbnRJbmRleCIsIm5ld1RyeXRlcyIsInRyYW5zYWN0aW9uVHJ5dGVzIiwiY3VybCIsIm5vbmNlIiwicmV0dXJuZWRUcnl0ZXMiLCJzdWJzdHIiLCJjb25jYXQiLCJuZXdUeE9iamVjdCIsInR4SGFzaCIsImhhc2giLCJwdXNoIiwid2luZG93IiwiaW5pdCIsImluc3RhbmNlIiwic2V0T2Zmc2V0IiwibyIsImludGVycnVwdCIsInJlc3VtZSIsImRvTmV4dCIsInJlbW92ZSIsInF1ZXVlIiwidW5zaGlmdCIsIldlYkdMIiwiU2VhcmNoSW5pdCIsIktSTkwiLCJURVhFTFNJWkUiLCJQRFN0YXRlIiwiUkVBRFkiLCJTRUFSQ0hJTkciLCJJTlRFUlJVUFRFRCIsInBhY2siLCJyIiwiayIsInBlYXJsRGl2ZXJDYWxsYmFjayIsInJlcyIsInRyYW5zYWN0aW9uVHJpdHMiLCJtaW5XZWlnaHRNYWduaXR1ZGUiLCJtX3NlbGYiLCJzZWFyY2hPYmplY3QiLCJQZWFybERpdmVySW5zdGFuY2UiLCJjb250ZXh0IiwiaW5jcmVtZW50IiwiY2hlY2siLCJjb2xfY2hlY2siLCJmaW5hbGl6ZSIsInN0YXRlcyIsIlByb21pc2UiLCJyZWplY3QiLCJyZWoiLCJtd20iLCJjYWxsIiwibmV4dCIsInNoaWZ0IiwiX1dlYkdMRmluZE5vbmNlIiwiX3NhdmUiLCJyZWR1Y2UiLCJhIiwiYyIsImZvckVhY2giLCJfV2ViR0xXcml0ZUJ1ZmZlcnMiLCJsb3ciLCJoaWdoIiwiX1dlYkdMU2VhcmNoIiwic2V0VGltZW91dCIsInNlYXJjaFdpdGhDYWxsYmFjayIsImVyciIsInRvUGFpciIsIlRSWVRFX0xFTkdUSCIsIkxPV19CSVRTIiwiSElHSF9CSVRTIiwiTE9XXzAiLCJMT1dfMSIsIkxPV18yIiwiTE9XXzMiLCJISUdIXzAiLCJISUdIXzEiLCJISUdIXzIiLCJISUdIXzMiLCJ0cml0Iiwic2NyYXRjaHBhZEhpZ2giLCJzY3JhdGNocGFkTG93Iiwic2NyYXRjaHBhZEluZGV4Iiwic3RhdGVJbmRleCIsImJldGEiLCJnYW1tYSIsImRlbHRhIiwiZG9fY2hlY2siLCJrX2NoZWNrIiwiY29sIiwiaGVhZGVycyIsImJhcnJpZXIiLCJ0d2lzdCIsImFkZCIsImtfaW5pdCIsInR3aXN0TWFpbiIsImtfdHJhbnNmb3JtIl0sIm1hcHBpbmdzIjoiQUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxDQUFDO0FBQ0QsTztBQ1ZBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOzs7QUFHQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxhQUFLO0FBQ0w7QUFDQTs7QUFFQTtBQUNBO0FBQ0EseURBQWlELGNBQWM7QUFDL0Q7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsbUNBQTJCLDBCQUEwQixFQUFFO0FBQ3ZELHlDQUFpQyxlQUFlO0FBQ2hEO0FBQ0E7QUFDQTs7QUFFQTtBQUNBLDhEQUFzRCwrREFBK0Q7O0FBRXJIO0FBQ0E7OztBQUdBO0FBQ0E7Ozs7Ozs7Ozs7OztBQ25FQSxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FB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QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxNQUFNO0FBQ04sRUFBRTs7O0FBR0YsQ0FBQyxHOzs7Ozs7Ozs7OztBQzlJRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDs7QUFFQSxDQUFDLEc7Ozs7Ozs7Ozs7O0FDakJELENBQUM7QUFDRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFFBT0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLDRCQUE0QiwwQkFBMEI7QUFDdEQ7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsVUFBVTtBQUNWO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EsRUFBRTs7O0FBR0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQzNFRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSx3QkFBd0IsUUFBUTtBQUNoQztBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQSw0QkFBNEIsUUFBUTtBQUNwQztBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQSw0QkFBNEIsT0FBTztBQUNuQztBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLE1BQU07O0FBRU47QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsZ0JBQWdCLGlCQUFpQjtBQUNqQztBQUNBLGlCQUFpQixVQUFVO0FBQzNCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSxnQkFBZ0IsaUJBQWlCO0FBQ2pDLGdCQUFnQixpQkFBaUI7QUFDakM7QUFDQSxpQkFBaUIsVUFBVTtBQUMzQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsRUFBRTs7O0FBR0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQzNRRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxVQUFVO0FBQ1Y7QUFDQTtBQUNBOztBQUVBO0FBQ0Esd0JBQXdCLGVBQWU7QUFDdkM7QUFDQTtBQUNBOztBQUVBO0FBQ0EsRUFBRTs7O0FBR0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQzdFRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0Esd0NBQXdDO0FBQ3hDO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLGVBQWU7QUFDM0M7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjs7QUFFQTtBQUNBLEVBQUU7Ozs7O0FBS0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQ25IRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQSw0QkFBNEIsZUFBZTtBQUMzQztBQUNBO0FBQ0E7QUFDQSxNQUFNOztBQUVOOztBQUVBO0FBQ0EsRUFBRTs7O0FBR0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQ3pERCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQTtBQUNBLE1BQU07O0FBRU47QUFDQSxFQUFFOzs7QUFHRjs7QUFFQSxDQUFDLEc7Ozs7Ozs7Ozs7O0FDdkNELENBQUM7QUFDRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFFBT0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLGVBQWU7QUFDM0M7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjs7QUFFQTtBQUNBLEVBQUU7OztBQUdGOztBQUVBLENBQUMsRzs7Ozs7Ozs7Ozs7QUNyREQsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFPQTtBQUNBLENBQUM7O0FBRUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQSxNQUFNOztBQUVOO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQ2hERCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLE1BQU07O0FBRU47QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTs7QUFFQSxDQUFDLEc7Ozs7Ozs7Ozs7O0FDM0NELENBQUM7QUFDRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFFBT0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxNQUFNOztBQUVOO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQ3ZDRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7OztBQUdBOztBQUVBLENBQUMsRzs7Ozs7Ozs7Ozs7QUM3QkQsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFPQTtBQUNBLENBQUM7O0FBRUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQzVDRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7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QTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVOztBQUVWOztBQUVBO0FBQ0EsNEJBQTRCLFFBQVE7QUFDcEM7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsNEJBQTRCLFFBQVE7QUFDcEM7QUFDQTtBQUNBO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCLE9BQU87QUFDekI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCLE9BQU87QUFDekI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLE9BQU87QUFDbkM7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLE1BQU07OztBQUdOO0FBQ0E7O0FBRUE7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTs7QUFFQTtBQUNBO0FBQ0E7OztB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Q0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLFFBQVE7QUFDcEM7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQjtBQUNsQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTs7QUFFQTtBQUNBLFVBQVU7O0FBRVY7QUFDQSxNQUFNOztBQUVOO0FBQ0E7QUFDQTtBQUNBLGdCQUFnQixpQkFBaUI7QUFDakM7QUFDQSxpQkFBaUIsVUFBVTtBQUMzQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsZ0JBQWdCLGlCQUFpQjtBQUNqQyxnQkFBZ0IsaUJBQWlCO0FBQ2pDO0FBQ0EsaUJBQWlCLFVBQVU7QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEVBQUU7OztBQUdGOztBQUVBLENBQUMsRzs7Ozs7Ozs7Ozs7QUNsVUQsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFPQTtBQUNBLENBQUM7O0FBRUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTtBQUNWO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVO0FBQ1Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7QUFDVjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTtBQUNWO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVO0FBQ1Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7QUFDVjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTtBQUNWO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNB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QU1vVSxRQUFhLG1CQUFBcFUsQ0FBUywrQ0FBVCxDQUFuQjtBQUNBLElBQU1tUixRQUFhLG1CQUFBblIsQ0FBUyx1Q0FBVCxDQUFuQjtBQUNBLElBQU1xVSxNQUFhLG1CQUFBclUsQ0FBUyxtQ0FBVCxDQUFuQjtBQUNBLElBQU1xUCxPQUFhLG1CQUFBclAsQ0FBUyxxQ0FBVCxDQUFuQjtBQUNBLElBQU1rUixZQUFhLG1CQUFBbFIsQ0FBUywrQ0FBVCxDQUFuQjs7QUFFQW9GLE9BQU9DLE9BQVAsR0FBaUI7QUFDZmdLLFFBQVk2RSxVQUFVRyxHQUFWLEdBQWdCaEYsSUFEYjtBQUVmNkIsYUFBWWdELFVBQVVHLEdBQVYsR0FBZ0JuRCxTQUZiO0FBR2ZyRyxhQUFZcUosVUFBVUUsS0FIUDtBQUlmaEQsYUFBWThDLFVBQVUvQyxNQUFNOEMsR0FKYjtBQUtmOUMsU0FBWStDLFVBQVUvQyxNQUFNNEMsUUFBaEIsR0FBMkI1QyxNQUFNNkMsT0FMOUI7QUFNZjNDLFlBQVk2QyxVQUFVL0MsTUFBTTRDLFFBQWhCLEdBQTJCMUM7QUFOeEIsQ0FBakIsQzs7Ozs7Ozs7Ozs7Ozs7QUNUQSxJQUFJaUQsK0RBQUo7QUFNQSxJQUFJNUosNFVBQUo7QUFZQXRGLE9BQU9DLE9BQVAsR0FBaUJxRixTQUFTNEosTUFBMUIsQzs7Ozs7Ozs7Ozs7Ozs7QUNsQkEsSUFBSUYsdWJBQUo7QUFnQkEsSUFBS0cscUpBQUw7O0FBVUEsSUFBSUMseVlBQUo7O0FBZ0JBcFAsT0FBT0MsT0FBUCxHQUFpQitPLFFBQVFHLFNBQXpCLEMiLCJmaWxlIjoiY3VybC5qcyIsInNvdXJjZXNDb250ZW50IjpbIihmdW5jdGlvbiB3ZWJwYWNrVW5pdmVyc2FsTW9kdWxlRGVmaW5pdGlvbihyb290LCBmYWN0b3J5KSB7XG5cdGlmKHR5cGVvZiBleHBvcnRzID09PSAnb2JqZWN0JyAmJiB0eXBlb2YgbW9kdWxlID09PSAnb2JqZWN0Jylcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGZhY3RvcnkoKTtcblx0ZWxzZSBpZih0eXBlb2YgZGVmaW5lID09PSAnZnVuY3Rpb24nICYmIGRlZmluZS5hbWQpXG5cdFx0ZGVmaW5lKFtdLCBmYWN0b3J5KTtcblx0ZWxzZSB7XG5cdFx0dmFyIGEgPSBmYWN0b3J5KCk7XG5cdFx0Zm9yKHZhciBpIGluIGEpICh0eXBlb2YgZXhwb3J0cyA9PT0gJ29iamVjdCcgPyBleHBvcnRzIDogcm9vdClbaV0gPSBhW2ldO1xuXHR9XG59KSh3aW5kb3csIGZ1bmN0aW9uKCkge1xucmV0dXJuICIsIiBcdC8vIFRoZSBtb2R1bGUgY2FjaGVcbiBcdHZhciBpbnN0YWxsZWRNb2R1bGVzID0ge307XG5cbiBcdC8vIFRoZSByZXF1aXJlIGZ1bmN0aW9uXG4gXHRmdW5jdGlvbiBfX3dlYnBhY2tfcmVxdWlyZV9fKG1vZHVsZUlkKSB7XG5cbiBcdFx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG4gXHRcdGlmKGluc3RhbGxlZE1vZHVsZXNbbW9kdWxlSWRdKSB7XG4gXHRcdFx0cmV0dXJuIGluc3RhbGxlZE1vZHVsZXNbbW9kdWxlSWRdLmV4cG9ydHM7XG4gXHRcdH1cbiBcdFx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcbiBcdFx0dmFyIG1vZHVsZSA9IGluc3RhbGxlZE1vZHVsZXNbbW9kdWxlSWRdID0ge1xuIFx0XHRcdGk6IG1vZHVsZUlkLFxuIFx0XHRcdGw6IGZhbHNlLFxuIFx0XHRcdGV4cG9ydHM6IHt9XG4gXHRcdH07XG5cbiBcdFx0Ly8gRXhlY3V0ZSB0aGUgbW9kdWxlIGZ1bmN0aW9uXG4gXHRcdG1vZHVsZXNbbW9kdWxlSWRdLmNhbGwobW9kdWxlLmV4cG9ydHMsIG1vZHVsZSwgbW9kdWxlLmV4cG9ydHMsIF9fd2VicGFja19yZXF1aXJlX18pO1xuXG4gXHRcdC8vIEZsYWcgdGhlIG1vZHVsZSBhcyBsb2FkZWRcbiBcdFx0bW9kdWxlLmwgPSB0cnVlO1xuXG4gXHRcdC8vIFJldHVybiB0aGUgZXhwb3J0cyBvZiB0aGUgbW9kdWxlXG4gXHRcdHJldHVybiBtb2R1bGUuZXhwb3J0cztcbiBcdH1cblxuXG4gXHQvLyBleHBvc2UgdGhlIG1vZHVsZXMgb2JqZWN0IChfX3dlYnBhY2tfbW9kdWxlc19fKVxuIFx0X193ZWJwYWNrX3JlcXVpcmVfXy5tID0gbW9kdWxlcztcblxuIFx0Ly8gZXhwb3NlIHRoZSBtb2R1bGUgY2FjaGVcbiBcdF9fd2VicGFja19yZXF1aXJlX18uYyA9IGluc3RhbGxlZE1vZHVsZXM7XG5cbiBcdC8vIGRlZmluZSBnZXR0ZXIgZnVuY3Rpb24gZm9yIGhhcm1vbnkgZXhwb3J0c1xuIFx0X193ZWJwYWNrX3JlcXVpcmVfXy5kID0gZnVuY3Rpb24oZXhwb3J0cywgbmFtZSwgZ2V0dGVyKSB7XG4gXHRcdGlmKCFfX3dlYnBhY2tfcmVxdWlyZV9fLm8oZXhwb3J0cywgbmFtZSkpIHtcbiBcdFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgbmFtZSwge1xuIFx0XHRcdFx0Y29uZmlndXJhYmxlOiBmYWxzZSxcbiBcdFx0XHRcdGVudW1lcmFibGU6IHRydWUsXG4gXHRcdFx0XHRnZXQ6IGdldHRlclxuIFx0XHRcdH0pO1xuIFx0XHR9XG4gXHR9O1xuXG4gXHQvLyBkZWZpbmUgX19lc01vZHVsZSBvbiBleHBvcnRzXG4gXHRfX3dlYnBhY2tfcmVxdWlyZV9fLnIgPSBmdW5jdGlvbihleHBvcnRzKSB7XG4gXHRcdE9iamVjdC5kZWZpbmVQcm9wZXJ0eShleHBvcnRzLCAnX19lc01vZHVsZScsIHsgdmFsdWU6IHRydWUgfSk7XG4gXHR9O1xuXG4gXHQvLyBnZXREZWZhdWx0RXhwb3J0IGZ1bmN0aW9uIGZvciBjb21wYXRpYmlsaXR5IHdpdGggbm9uLWhhcm1vbnkgbW9kdWxlc1xuIFx0X193ZWJwYWNrX3JlcXVpcmVfXy5uID0gZnVuY3Rpb24obW9kdWxlKSB7XG4gXHRcdHZhciBnZXR0ZXIgPSBtb2R1bGUgJiYgbW9kdWxlLl9fZXNNb2R1bGUgP1xuIFx0XHRcdGZ1bmN0aW9uIGdldERlZmF1bHQoKSB7IHJldHVybiBtb2R1bGVbJ2RlZmF1bHQnXTsgfSA6XG4gXHRcdFx0ZnVuY3Rpb24gZ2V0TW9kdWxlRXhwb3J0cygpIHsgcmV0dXJuIG1vZHVsZTsgfTtcbiBcdFx0X193ZWJwYWNrX3JlcXVpcmVfXy5kKGdldHRlciwgJ2EnLCBnZXR0ZXIpO1xuIFx0XHRyZXR1cm4gZ2V0dGVyO1xuIFx0fTtcblxuIFx0Ly8gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsXG4gXHRfX3dlYnBhY2tfcmVxdWlyZV9fLm8gPSBmdW5jdGlvbihvYmplY3QsIHByb3BlcnR5KSB7IHJldHVybiBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwob2JqZWN0LCBwcm9wZXJ0eSk7IH07XG5cbiBcdC8vIF9fd2VicGFja19wdWJsaWNfcGF0aF9fXG4gXHRfX3dlYnBhY2tfcmVxdWlyZV9fLnAgPSBcIi9kaXN0XCI7XG5cblxuIFx0Ly8gTG9hZCBlbnRyeSBtb2R1bGUgYW5kIHJldHVybiBleHBvcnRzXG4gXHRyZXR1cm4gX193ZWJwYWNrX3JlcXVpcmVfXyhfX3dlYnBhY2tfcmVxdWlyZV9fLnMgPSBcIi4vc3JjL2N1cmwubGliLmpzXCIpO1xuIiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2VuYy1iYXNlNjRcIiksIHJlcXVpcmUoXCIuL21kNVwiKSwgcmVxdWlyZShcIi4vZXZwa2RmXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9lbmMtYmFzZTY0XCIsIFwiLi9tZDVcIiwgXCIuL2V2cGtkZlwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBCbG9ja0NpcGhlciA9IENfbGliLkJsb2NrQ2lwaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gTG9va3VwIHRhYmxlc1xuXHQgICAgdmFyIFNCT1ggPSBbXTtcblx0ICAgIHZhciBJTlZfU0JPWCA9IFtdO1xuXHQgICAgdmFyIFNVQl9NSVhfMCA9IFtdO1xuXHQgICAgdmFyIFNVQl9NSVhfMSA9IFtdO1xuXHQgICAgdmFyIFNVQl9NSVhfMiA9IFtdO1xuXHQgICAgdmFyIFNVQl9NSVhfMyA9IFtdO1xuXHQgICAgdmFyIElOVl9TVUJfTUlYXzAgPSBbXTtcblx0ICAgIHZhciBJTlZfU1VCX01JWF8xID0gW107XG5cdCAgICB2YXIgSU5WX1NVQl9NSVhfMiA9IFtdO1xuXHQgICAgdmFyIElOVl9TVUJfTUlYXzMgPSBbXTtcblxuXHQgICAgLy8gQ29tcHV0ZSBsb29rdXAgdGFibGVzXG5cdCAgICAoZnVuY3Rpb24gKCkge1xuXHQgICAgICAgIC8vIENvbXB1dGUgZG91YmxlIHRhYmxlXG5cdCAgICAgICAgdmFyIGQgPSBbXTtcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI1NjsgaSsrKSB7XG5cdCAgICAgICAgICAgIGlmIChpIDwgMTI4KSB7XG5cdCAgICAgICAgICAgICAgICBkW2ldID0gaSA8PCAxO1xuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgZFtpXSA9IChpIDw8IDEpIF4gMHgxMWI7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cblx0ICAgICAgICAvLyBXYWxrIEdGKDJeOClcblx0ICAgICAgICB2YXIgeCA9IDA7XG5cdCAgICAgICAgdmFyIHhpID0gMDtcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI1NjsgaSsrKSB7XG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgc2JveFxuXHQgICAgICAgICAgICB2YXIgc3ggPSB4aSBeICh4aSA8PCAxKSBeICh4aSA8PCAyKSBeICh4aSA8PCAzKSBeICh4aSA8PCA0KTtcblx0ICAgICAgICAgICAgc3ggPSAoc3ggPj4+IDgpIF4gKHN4ICYgMHhmZikgXiAweDYzO1xuXHQgICAgICAgICAgICBTQk9YW3hdID0gc3g7XG5cdCAgICAgICAgICAgIElOVl9TQk9YW3N4XSA9IHg7XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBtdWx0aXBsaWNhdGlvblxuXHQgICAgICAgICAgICB2YXIgeDIgPSBkW3hdO1xuXHQgICAgICAgICAgICB2YXIgeDQgPSBkW3gyXTtcblx0ICAgICAgICAgICAgdmFyIHg4ID0gZFt4NF07XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBzdWIgYnl0ZXMsIG1peCBjb2x1bW5zIHRhYmxlc1xuXHQgICAgICAgICAgICB2YXIgdCA9IChkW3N4XSAqIDB4MTAxKSBeIChzeCAqIDB4MTAxMDEwMCk7XG5cdCAgICAgICAgICAgIFNVQl9NSVhfMFt4XSA9ICh0IDw8IDI0KSB8ICh0ID4+PiA4KTtcblx0ICAgICAgICAgICAgU1VCX01JWF8xW3hdID0gKHQgPDwgMTYpIHwgKHQgPj4+IDE2KTtcblx0ICAgICAgICAgICAgU1VCX01JWF8yW3hdID0gKHQgPDwgOCkgIHwgKHQgPj4+IDI0KTtcblx0ICAgICAgICAgICAgU1VCX01JWF8zW3hdID0gdDtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRlIGludiBzdWIgYnl0ZXMsIGludiBtaXggY29sdW1ucyB0YWJsZXNcblx0ICAgICAgICAgICAgdmFyIHQgPSAoeDggKiAweDEwMTAxMDEpIF4gKHg0ICogMHgxMDAwMSkgXiAoeDIgKiAweDEwMSkgXiAoeCAqIDB4MTAxMDEwMCk7XG5cdCAgICAgICAgICAgIElOVl9TVUJfTUlYXzBbc3hdID0gKHQgPDwgMjQpIHwgKHQgPj4+IDgpO1xuXHQgICAgICAgICAgICBJTlZfU1VCX01JWF8xW3N4XSA9ICh0IDw8IDE2KSB8ICh0ID4+PiAxNik7XG5cdCAgICAgICAgICAgIElOVl9TVUJfTUlYXzJbc3hdID0gKHQgPDwgOCkgIHwgKHQgPj4+IDI0KTtcblx0ICAgICAgICAgICAgSU5WX1NVQl9NSVhfM1tzeF0gPSB0O1xuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgbmV4dCBjb3VudGVyXG5cdCAgICAgICAgICAgIGlmICgheCkge1xuXHQgICAgICAgICAgICAgICAgeCA9IHhpID0gMTtcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIHggPSB4MiBeIGRbZFtkW3g4IF4geDJdXV07XG5cdCAgICAgICAgICAgICAgICB4aSBePSBkW2RbeGldXTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH1cblx0ICAgIH0oKSk7XG5cblx0ICAgIC8vIFByZWNvbXB1dGVkIFJjb24gbG9va3VwXG5cdCAgICB2YXIgUkNPTiA9IFsweDAwLCAweDAxLCAweDAyLCAweDA0LCAweDA4LCAweDEwLCAweDIwLCAweDQwLCAweDgwLCAweDFiLCAweDM2XTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBRVMgYmxvY2sgY2lwaGVyIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIEFFUyA9IENfYWxnby5BRVMgPSBCbG9ja0NpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNraXAgcmVzZXQgb2YgblJvdW5kcyBoYXMgYmVlbiBzZXQgYmVmb3JlIGFuZCBrZXkgZGlkIG5vdCBjaGFuZ2Vcblx0ICAgICAgICAgICAgaWYgKHRoaXMuX25Sb3VuZHMgJiYgdGhpcy5fa2V5UHJpb3JSZXNldCA9PT0gdGhpcy5fa2V5KSB7XG5cdCAgICAgICAgICAgICAgICByZXR1cm47XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGtleSA9IHRoaXMuX2tleVByaW9yUmVzZXQgPSB0aGlzLl9rZXk7XG5cdCAgICAgICAgICAgIHZhciBrZXlXb3JkcyA9IGtleS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIGtleVNpemUgPSBrZXkuc2lnQnl0ZXMgLyA0O1xuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgbnVtYmVyIG9mIHJvdW5kc1xuXHQgICAgICAgICAgICB2YXIgblJvdW5kcyA9IHRoaXMuX25Sb3VuZHMgPSBrZXlTaXplICsgNjtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRlIG51bWJlciBvZiBrZXkgc2NoZWR1bGUgcm93c1xuXHQgICAgICAgICAgICB2YXIga3NSb3dzID0gKG5Sb3VuZHMgKyAxKSAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBrZXkgc2NoZWR1bGVcblx0ICAgICAgICAgICAgdmFyIGtleVNjaGVkdWxlID0gdGhpcy5fa2V5U2NoZWR1bGUgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIga3NSb3cgPSAwOyBrc1JvdyA8IGtzUm93czsga3NSb3crKykge1xuXHQgICAgICAgICAgICAgICAgaWYgKGtzUm93IDwga2V5U2l6ZSkge1xuXHQgICAgICAgICAgICAgICAgICAgIGtleVNjaGVkdWxlW2tzUm93XSA9IGtleVdvcmRzW2tzUm93XTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIHQgPSBrZXlTY2hlZHVsZVtrc1JvdyAtIDFdO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgaWYgKCEoa3NSb3cgJSBrZXlTaXplKSkge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICAvLyBSb3Qgd29yZFxuXHQgICAgICAgICAgICAgICAgICAgICAgICB0ID0gKHQgPDwgOCkgfCAodCA+Pj4gMjQpO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgICAgIC8vIFN1YiB3b3JkXG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHQgPSAoU0JPWFt0ID4+PiAyNF0gPDwgMjQpIHwgKFNCT1hbKHQgPj4+IDE2KSAmIDB4ZmZdIDw8IDE2KSB8IChTQk9YWyh0ID4+PiA4KSAmIDB4ZmZdIDw8IDgpIHwgU0JPWFt0ICYgMHhmZl07XG5cblx0ICAgICAgICAgICAgICAgICAgICAgICAgLy8gTWl4IFJjb25cblx0ICAgICAgICAgICAgICAgICAgICAgICAgdCBePSBSQ09OWyhrc1JvdyAvIGtleVNpemUpIHwgMF0gPDwgMjQ7XG5cdCAgICAgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChrZXlTaXplID4gNiAmJiBrc1JvdyAlIGtleVNpemUgPT0gNCkge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICAvLyBTdWIgd29yZFxuXHQgICAgICAgICAgICAgICAgICAgICAgICB0ID0gKFNCT1hbdCA+Pj4gMjRdIDw8IDI0KSB8IChTQk9YWyh0ID4+PiAxNikgJiAweGZmXSA8PCAxNikgfCAoU0JPWFsodCA+Pj4gOCkgJiAweGZmXSA8PCA4KSB8IFNCT1hbdCAmIDB4ZmZdO1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgICAgIGtleVNjaGVkdWxlW2tzUm93XSA9IGtleVNjaGVkdWxlW2tzUm93IC0ga2V5U2l6ZV0gXiB0O1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBpbnYga2V5IHNjaGVkdWxlXG5cdCAgICAgICAgICAgIHZhciBpbnZLZXlTY2hlZHVsZSA9IHRoaXMuX2ludktleVNjaGVkdWxlID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGludktzUm93ID0gMDsgaW52S3NSb3cgPCBrc1Jvd3M7IGludktzUm93KyspIHtcblx0ICAgICAgICAgICAgICAgIHZhciBrc1JvdyA9IGtzUm93cyAtIGludktzUm93O1xuXG5cdCAgICAgICAgICAgICAgICBpZiAoaW52S3NSb3cgJSA0KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIHQgPSBrZXlTY2hlZHVsZVtrc1Jvd107XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciB0ID0ga2V5U2NoZWR1bGVba3NSb3cgLSA0XTtcblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgaWYgKGludktzUm93IDwgNCB8fCBrc1JvdyA8PSA0KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgaW52S2V5U2NoZWR1bGVbaW52S3NSb3ddID0gdDtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICAgICAgaW52S2V5U2NoZWR1bGVbaW52S3NSb3ddID0gSU5WX1NVQl9NSVhfMFtTQk9YW3QgPj4+IDI0XV0gXiBJTlZfU1VCX01JWF8xW1NCT1hbKHQgPj4+IDE2KSAmIDB4ZmZdXSBeXG5cdCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgSU5WX1NVQl9NSVhfMltTQk9YWyh0ID4+PiA4KSAmIDB4ZmZdXSBeIElOVl9TVUJfTUlYXzNbU0JPWFt0ICYgMHhmZl1dO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGVuY3J5cHRCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICB0aGlzLl9kb0NyeXB0QmxvY2soTSwgb2Zmc2V0LCB0aGlzLl9rZXlTY2hlZHVsZSwgU1VCX01JWF8wLCBTVUJfTUlYXzEsIFNVQl9NSVhfMiwgU1VCX01JWF8zLCBTQk9YKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgZGVjcnlwdEJsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIC8vIFN3YXAgMm5kIGFuZCA0dGggcm93c1xuXHQgICAgICAgICAgICB2YXIgdCA9IE1bb2Zmc2V0ICsgMV07XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0ICsgMV0gPSBNW29mZnNldCArIDNdO1xuXHQgICAgICAgICAgICBNW29mZnNldCArIDNdID0gdDtcblxuXHQgICAgICAgICAgICB0aGlzLl9kb0NyeXB0QmxvY2soTSwgb2Zmc2V0LCB0aGlzLl9pbnZLZXlTY2hlZHVsZSwgSU5WX1NVQl9NSVhfMCwgSU5WX1NVQl9NSVhfMSwgSU5WX1NVQl9NSVhfMiwgSU5WX1NVQl9NSVhfMywgSU5WX1NCT1gpO1xuXG5cdCAgICAgICAgICAgIC8vIEludiBzd2FwIDJuZCBhbmQgNHRoIHJvd3Ncblx0ICAgICAgICAgICAgdmFyIHQgPSBNW29mZnNldCArIDFdO1xuXHQgICAgICAgICAgICBNW29mZnNldCArIDFdID0gTVtvZmZzZXQgKyAzXTtcblx0ICAgICAgICAgICAgTVtvZmZzZXQgKyAzXSA9IHQ7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0NyeXB0QmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQsIGtleVNjaGVkdWxlLCBTVUJfTUlYXzAsIFNVQl9NSVhfMSwgU1VCX01JWF8yLCBTVUJfTUlYXzMsIFNCT1gpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIG5Sb3VuZHMgPSB0aGlzLl9uUm91bmRzO1xuXG5cdCAgICAgICAgICAgIC8vIEdldCBpbnB1dCwgYWRkIHJvdW5kIGtleVxuXHQgICAgICAgICAgICB2YXIgczAgPSBNW29mZnNldF0gICAgIF4ga2V5U2NoZWR1bGVbMF07XG5cdCAgICAgICAgICAgIHZhciBzMSA9IE1bb2Zmc2V0ICsgMV0gXiBrZXlTY2hlZHVsZVsxXTtcblx0ICAgICAgICAgICAgdmFyIHMyID0gTVtvZmZzZXQgKyAyXSBeIGtleVNjaGVkdWxlWzJdO1xuXHQgICAgICAgICAgICB2YXIgczMgPSBNW29mZnNldCArIDNdIF4ga2V5U2NoZWR1bGVbM107XG5cblx0ICAgICAgICAgICAgLy8gS2V5IHNjaGVkdWxlIHJvdyBjb3VudGVyXG5cdCAgICAgICAgICAgIHZhciBrc1JvdyA9IDQ7XG5cblx0ICAgICAgICAgICAgLy8gUm91bmRzXG5cdCAgICAgICAgICAgIGZvciAodmFyIHJvdW5kID0gMTsgcm91bmQgPCBuUm91bmRzOyByb3VuZCsrKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTaGlmdCByb3dzLCBzdWIgYnl0ZXMsIG1peCBjb2x1bW5zLCBhZGQgcm91bmQga2V5XG5cdCAgICAgICAgICAgICAgICB2YXIgdDAgPSBTVUJfTUlYXzBbczAgPj4+IDI0XSBeIFNVQl9NSVhfMVsoczEgPj4+IDE2KSAmIDB4ZmZdIF4gU1VCX01JWF8yWyhzMiA+Pj4gOCkgJiAweGZmXSBeIFNVQl9NSVhfM1tzMyAmIDB4ZmZdIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cdCAgICAgICAgICAgICAgICB2YXIgdDEgPSBTVUJfTUlYXzBbczEgPj4+IDI0XSBeIFNVQl9NSVhfMVsoczIgPj4+IDE2KSAmIDB4ZmZdIF4gU1VCX01JWF8yWyhzMyA+Pj4gOCkgJiAweGZmXSBeIFNVQl9NSVhfM1tzMCAmIDB4ZmZdIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cdCAgICAgICAgICAgICAgICB2YXIgdDIgPSBTVUJfTUlYXzBbczIgPj4+IDI0XSBeIFNVQl9NSVhfMVsoczMgPj4+IDE2KSAmIDB4ZmZdIF4gU1VCX01JWF8yWyhzMCA+Pj4gOCkgJiAweGZmXSBeIFNVQl9NSVhfM1tzMSAmIDB4ZmZdIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cdCAgICAgICAgICAgICAgICB2YXIgdDMgPSBTVUJfTUlYXzBbczMgPj4+IDI0XSBeIFNVQl9NSVhfMVsoczAgPj4+IDE2KSAmIDB4ZmZdIF4gU1VCX01JWF8yWyhzMSA+Pj4gOCkgJiAweGZmXSBeIFNVQl9NSVhfM1tzMiAmIDB4ZmZdIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cblx0ICAgICAgICAgICAgICAgIC8vIFVwZGF0ZSBzdGF0ZVxuXHQgICAgICAgICAgICAgICAgczAgPSB0MDtcblx0ICAgICAgICAgICAgICAgIHMxID0gdDE7XG5cdCAgICAgICAgICAgICAgICBzMiA9IHQyO1xuXHQgICAgICAgICAgICAgICAgczMgPSB0Mztcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFNoaWZ0IHJvd3MsIHN1YiBieXRlcywgYWRkIHJvdW5kIGtleVxuXHQgICAgICAgICAgICB2YXIgdDAgPSAoKFNCT1hbczAgPj4+IDI0XSA8PCAyNCkgfCAoU0JPWFsoczEgPj4+IDE2KSAmIDB4ZmZdIDw8IDE2KSB8IChTQk9YWyhzMiA+Pj4gOCkgJiAweGZmXSA8PCA4KSB8IFNCT1hbczMgJiAweGZmXSkgXiBrZXlTY2hlZHVsZVtrc1JvdysrXTtcblx0ICAgICAgICAgICAgdmFyIHQxID0gKChTQk9YW3MxID4+PiAyNF0gPDwgMjQpIHwgKFNCT1hbKHMyID4+PiAxNikgJiAweGZmXSA8PCAxNikgfCAoU0JPWFsoczMgPj4+IDgpICYgMHhmZl0gPDwgOCkgfCBTQk9YW3MwICYgMHhmZl0pIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cdCAgICAgICAgICAgIHZhciB0MiA9ICgoU0JPWFtzMiA+Pj4gMjRdIDw8IDI0KSB8IChTQk9YWyhzMyA+Pj4gMTYpICYgMHhmZl0gPDwgMTYpIHwgKFNCT1hbKHMwID4+PiA4KSAmIDB4ZmZdIDw8IDgpIHwgU0JPWFtzMSAmIDB4ZmZdKSBeIGtleVNjaGVkdWxlW2tzUm93KytdO1xuXHQgICAgICAgICAgICB2YXIgdDMgPSAoKFNCT1hbczMgPj4+IDI0XSA8PCAyNCkgfCAoU0JPWFsoczAgPj4+IDE2KSAmIDB4ZmZdIDw8IDE2KSB8IChTQk9YWyhzMSA+Pj4gOCkgJiAweGZmXSA8PCA4KSB8IFNCT1hbczIgJiAweGZmXSkgXiBrZXlTY2hlZHVsZVtrc1JvdysrXTtcblxuXHQgICAgICAgICAgICAvLyBTZXQgb3V0cHV0XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0XSAgICAgPSB0MDtcblx0ICAgICAgICAgICAgTVtvZmZzZXQgKyAxXSA9IHQxO1xuXHQgICAgICAgICAgICBNW29mZnNldCArIDJdID0gdDI7XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0ICsgM10gPSB0Mztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAga2V5U2l6ZTogMjU2LzMyXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbnMgdG8gdGhlIGNpcGhlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGNpcGhlcnRleHQgPSBDcnlwdG9KUy5BRVMuZW5jcnlwdChtZXNzYWdlLCBrZXksIGNmZyk7XG5cdCAgICAgKiAgICAgdmFyIHBsYWludGV4dCAgPSBDcnlwdG9KUy5BRVMuZGVjcnlwdChjaXBoZXJ0ZXh0LCBrZXksIGNmZyk7XG5cdCAgICAgKi9cblx0ICAgIEMuQUVTID0gQmxvY2tDaXBoZXIuX2NyZWF0ZUhlbHBlcihBRVMpO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLkFFUztcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9ldnBrZGZcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vZXZwa2RmXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogQ2lwaGVyIGNvcmUgY29tcG9uZW50cy5cblx0ICovXG5cdENyeXB0b0pTLmxpYi5DaXBoZXIgfHwgKGZ1bmN0aW9uICh1bmRlZmluZWQpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIEJhc2UgPSBDX2xpYi5CYXNlO1xuXHQgICAgdmFyIFdvcmRBcnJheSA9IENfbGliLldvcmRBcnJheTtcblx0ICAgIHZhciBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtID0gQ19saWIuQnVmZmVyZWRCbG9ja0FsZ29yaXRobTtcblx0ICAgIHZhciBDX2VuYyA9IEMuZW5jO1xuXHQgICAgdmFyIFV0ZjggPSBDX2VuYy5VdGY4O1xuXHQgICAgdmFyIEJhc2U2NCA9IENfZW5jLkJhc2U2NDtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cdCAgICB2YXIgRXZwS0RGID0gQ19hbGdvLkV2cEtERjtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBYnN0cmFjdCBiYXNlIGNpcGhlciB0ZW1wbGF0ZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcHJvcGVydHkge251bWJlcn0ga2V5U2l6ZSBUaGlzIGNpcGhlcidzIGtleSBzaXplLiBEZWZhdWx0OiA0ICgxMjggYml0cylcblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBpdlNpemUgVGhpcyBjaXBoZXIncyBJViBzaXplLiBEZWZhdWx0OiA0ICgxMjggYml0cylcblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBfRU5DX1hGT1JNX01PREUgQSBjb25zdGFudCByZXByZXNlbnRpbmcgZW5jcnlwdGlvbiBtb2RlLlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IF9ERUNfWEZPUk1fTU9ERSBBIGNvbnN0YW50IHJlcHJlc2VudGluZyBkZWNyeXB0aW9uIG1vZGUuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDaXBoZXIgPSBDX2xpYi5DaXBoZXIgPSBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtXb3JkQXJyYXl9IGl2IFRoZSBJViB0byB1c2UgZm9yIHRoaXMgb3BlcmF0aW9uLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNmZzogQmFzZS5leHRlbmQoKSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgdGhpcyBjaXBoZXIgaW4gZW5jcnlwdGlvbiBtb2RlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGtleSBUaGUga2V5LlxuXHQgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJ9IEEgY2lwaGVyIGluc3RhbmNlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVyID0gQ3J5cHRvSlMuYWxnby5BRVMuY3JlYXRlRW5jcnlwdG9yKGtleVdvcmRBcnJheSwgeyBpdjogaXZXb3JkQXJyYXkgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY3JlYXRlRW5jcnlwdG9yOiBmdW5jdGlvbiAoa2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlKHRoaXMuX0VOQ19YRk9STV9NT0RFLCBrZXksIGNmZyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgdGhpcyBjaXBoZXIgaW4gZGVjcnlwdGlvbiBtb2RlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGtleSBUaGUga2V5LlxuXHQgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJ9IEEgY2lwaGVyIGluc3RhbmNlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVyID0gQ3J5cHRvSlMuYWxnby5BRVMuY3JlYXRlRGVjcnlwdG9yKGtleVdvcmRBcnJheSwgeyBpdjogaXZXb3JkQXJyYXkgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY3JlYXRlRGVjcnlwdG9yOiBmdW5jdGlvbiAoa2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXMuY3JlYXRlKHRoaXMuX0RFQ19YRk9STV9NT0RFLCBrZXksIGNmZyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCBjaXBoZXIuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0geGZvcm1Nb2RlIEVpdGhlciB0aGUgZW5jcnlwdGlvbiBvciBkZWNyeXB0aW9uIHRyYW5zb3JtYXRpb24gbW9kZSBjb25zdGFudC5cblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0ga2V5IFRoZSBrZXkuXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlciA9IENyeXB0b0pTLmFsZ28uQUVTLmNyZWF0ZShDcnlwdG9KUy5hbGdvLkFFUy5fRU5DX1hGT1JNX01PREUsIGtleVdvcmRBcnJheSwgeyBpdjogaXZXb3JkQXJyYXkgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKHhmb3JtTW9kZSwga2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIHRoaXMuY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gU3RvcmUgdHJhbnNmb3JtIG1vZGUgYW5kIGtleVxuXHQgICAgICAgICAgICB0aGlzLl94Zm9ybU1vZGUgPSB4Zm9ybU1vZGU7XG5cdCAgICAgICAgICAgIHRoaXMuX2tleSA9IGtleTtcblxuXHQgICAgICAgICAgICAvLyBTZXQgaW5pdGlhbCB2YWx1ZXNcblx0ICAgICAgICAgICAgdGhpcy5yZXNldCgpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBSZXNldHMgdGhpcyBjaXBoZXIgdG8gaXRzIGluaXRpYWwgc3RhdGUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIGNpcGhlci5yZXNldCgpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHJlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFJlc2V0IGRhdGEgYnVmZmVyXG5cdCAgICAgICAgICAgIEJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0ucmVzZXQuY2FsbCh0aGlzKTtcblxuXHQgICAgICAgICAgICAvLyBQZXJmb3JtIGNvbmNyZXRlLWNpcGhlciBsb2dpY1xuXHQgICAgICAgICAgICB0aGlzLl9kb1Jlc2V0KCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEFkZHMgZGF0YSB0byBiZSBlbmNyeXB0ZWQgb3IgZGVjcnlwdGVkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBkYXRhVXBkYXRlIFRoZSBkYXRhIHRvIGVuY3J5cHQgb3IgZGVjcnlwdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGRhdGEgYWZ0ZXIgcHJvY2Vzc2luZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGVuY3J5cHRlZCA9IGNpcGhlci5wcm9jZXNzKCdkYXRhJyk7XG5cdCAgICAgICAgICogICAgIHZhciBlbmNyeXB0ZWQgPSBjaXBoZXIucHJvY2Vzcyh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHByb2Nlc3M6IGZ1bmN0aW9uIChkYXRhVXBkYXRlKSB7XG5cdCAgICAgICAgICAgIC8vIEFwcGVuZFxuXHQgICAgICAgICAgICB0aGlzLl9hcHBlbmQoZGF0YVVwZGF0ZSk7XG5cblx0ICAgICAgICAgICAgLy8gUHJvY2VzcyBhdmFpbGFibGUgYmxvY2tzXG5cdCAgICAgICAgICAgIHJldHVybiB0aGlzLl9wcm9jZXNzKCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEZpbmFsaXplcyB0aGUgZW5jcnlwdGlvbiBvciBkZWNyeXB0aW9uIHByb2Nlc3MuXG5cdCAgICAgICAgICogTm90ZSB0aGF0IHRoZSBmaW5hbGl6ZSBvcGVyYXRpb24gaXMgZWZmZWN0aXZlbHkgYSBkZXN0cnVjdGl2ZSwgcmVhZC1vbmNlIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gZGF0YVVwZGF0ZSBUaGUgZmluYWwgZGF0YSB0byBlbmNyeXB0IG9yIGRlY3J5cHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBkYXRhIGFmdGVyIGZpbmFsIHByb2Nlc3NpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBlbmNyeXB0ZWQgPSBjaXBoZXIuZmluYWxpemUoKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGVuY3J5cHRlZCA9IGNpcGhlci5maW5hbGl6ZSgnZGF0YScpO1xuXHQgICAgICAgICAqICAgICB2YXIgZW5jcnlwdGVkID0gY2lwaGVyLmZpbmFsaXplKHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgZmluYWxpemU6IGZ1bmN0aW9uIChkYXRhVXBkYXRlKSB7XG5cdCAgICAgICAgICAgIC8vIEZpbmFsIGRhdGEgdXBkYXRlXG5cdCAgICAgICAgICAgIGlmIChkYXRhVXBkYXRlKSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9hcHBlbmQoZGF0YVVwZGF0ZSk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBQZXJmb3JtIGNvbmNyZXRlLWNpcGhlciBsb2dpY1xuXHQgICAgICAgICAgICB2YXIgZmluYWxQcm9jZXNzZWREYXRhID0gdGhpcy5fZG9GaW5hbGl6ZSgpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBmaW5hbFByb2Nlc3NlZERhdGE7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGtleVNpemU6IDEyOC8zMixcblxuXHQgICAgICAgIGl2U2l6ZTogMTI4LzMyLFxuXG5cdCAgICAgICAgX0VOQ19YRk9STV9NT0RFOiAxLFxuXG5cdCAgICAgICAgX0RFQ19YRk9STV9NT0RFOiAyLFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyBzaG9ydGN1dCBmdW5jdGlvbnMgdG8gYSBjaXBoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBUaGUgY2lwaGVyIHRvIGNyZWF0ZSBhIGhlbHBlciBmb3IuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtPYmplY3R9IEFuIG9iamVjdCB3aXRoIGVuY3J5cHQgYW5kIGRlY3J5cHQgc2hvcnRjdXQgZnVuY3Rpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgQUVTID0gQ3J5cHRvSlMubGliLkNpcGhlci5fY3JlYXRlSGVscGVyKENyeXB0b0pTLmFsZ28uQUVTKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBfY3JlYXRlSGVscGVyOiAoZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICBmdW5jdGlvbiBzZWxlY3RDaXBoZXJTdHJhdGVneShrZXkpIHtcblx0ICAgICAgICAgICAgICAgIGlmICh0eXBlb2Yga2V5ID09ICdzdHJpbmcnKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFBhc3N3b3JkQmFzZWRDaXBoZXI7XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgICAgIHJldHVybiBTZXJpYWxpemFibGVDaXBoZXI7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gZnVuY3Rpb24gKGNpcGhlcikge1xuXHQgICAgICAgICAgICAgICAgcmV0dXJuIHtcblx0ICAgICAgICAgICAgICAgICAgICBlbmNyeXB0OiBmdW5jdGlvbiAobWVzc2FnZSwga2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHNlbGVjdENpcGhlclN0cmF0ZWd5KGtleSkuZW5jcnlwdChjaXBoZXIsIG1lc3NhZ2UsIGtleSwgY2ZnKTtcblx0ICAgICAgICAgICAgICAgICAgICB9LFxuXG5cdCAgICAgICAgICAgICAgICAgICAgZGVjcnlwdDogZnVuY3Rpb24gKGNpcGhlcnRleHQsIGtleSwgY2ZnKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBzZWxlY3RDaXBoZXJTdHJhdGVneShrZXkpLmRlY3J5cHQoY2lwaGVyLCBjaXBoZXJ0ZXh0LCBrZXksIGNmZyk7XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgfTtcblx0ICAgICAgICAgICAgfTtcblx0ICAgICAgICB9KCkpXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBYnN0cmFjdCBiYXNlIHN0cmVhbSBjaXBoZXIgdGVtcGxhdGUuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IGJsb2NrU2l6ZSBUaGUgbnVtYmVyIG9mIDMyLWJpdCB3b3JkcyB0aGlzIGNpcGhlciBvcGVyYXRlcyBvbi4gRGVmYXVsdDogMSAoMzIgYml0cylcblx0ICAgICAqL1xuXHQgICAgdmFyIFN0cmVhbUNpcGhlciA9IENfbGliLlN0cmVhbUNpcGhlciA9IENpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb0ZpbmFsaXplOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFByb2Nlc3MgcGFydGlhbCBibG9ja3Ncblx0ICAgICAgICAgICAgdmFyIGZpbmFsUHJvY2Vzc2VkQmxvY2tzID0gdGhpcy5fcHJvY2VzcyghISdmbHVzaCcpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBmaW5hbFByb2Nlc3NlZEJsb2Nrcztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgYmxvY2tTaXplOiAxXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBNb2RlIG5hbWVzcGFjZS5cblx0ICAgICAqL1xuXHQgICAgdmFyIENfbW9kZSA9IEMubW9kZSA9IHt9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFic3RyYWN0IGJhc2UgYmxvY2sgY2lwaGVyIG1vZGUgdGVtcGxhdGUuXG5cdCAgICAgKi9cblx0ICAgIHZhciBCbG9ja0NpcGhlck1vZGUgPSBDX2xpYi5CbG9ja0NpcGhlck1vZGUgPSBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyB0aGlzIG1vZGUgZm9yIGVuY3J5cHRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0NpcGhlcn0gY2lwaGVyIEEgYmxvY2sgY2lwaGVyIGluc3RhbmNlLlxuXHQgICAgICAgICAqIEBwYXJhbSB7QXJyYXl9IGl2IFRoZSBJViB3b3Jkcy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIG1vZGUgPSBDcnlwdG9KUy5tb2RlLkNCQy5jcmVhdGVFbmNyeXB0b3IoY2lwaGVyLCBpdi53b3Jkcyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY3JlYXRlRW5jcnlwdG9yOiBmdW5jdGlvbiAoY2lwaGVyLCBpdikge1xuXHQgICAgICAgICAgICByZXR1cm4gdGhpcy5FbmNyeXB0b3IuY3JlYXRlKGNpcGhlciwgaXYpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDcmVhdGVzIHRoaXMgbW9kZSBmb3IgZGVjcnlwdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyfSBjaXBoZXIgQSBibG9jayBjaXBoZXIgaW5zdGFuY2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtBcnJheX0gaXYgVGhlIElWIHdvcmRzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgbW9kZSA9IENyeXB0b0pTLm1vZGUuQ0JDLmNyZWF0ZURlY3J5cHRvcihjaXBoZXIsIGl2LndvcmRzKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjcmVhdGVEZWNyeXB0b3I6IGZ1bmN0aW9uIChjaXBoZXIsIGl2KSB7XG5cdCAgICAgICAgICAgIHJldHVybiB0aGlzLkRlY3J5cHRvci5jcmVhdGUoY2lwaGVyLCBpdik7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCBtb2RlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBBIGJsb2NrIGNpcGhlciBpbnN0YW5jZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge0FycmF5fSBpdiBUaGUgSVYgd29yZHMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBtb2RlID0gQ3J5cHRvSlMubW9kZS5DQkMuRW5jcnlwdG9yLmNyZWF0ZShjaXBoZXIsIGl2LndvcmRzKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoY2lwaGVyLCBpdikge1xuXHQgICAgICAgICAgICB0aGlzLl9jaXBoZXIgPSBjaXBoZXI7XG5cdCAgICAgICAgICAgIHRoaXMuX2l2ID0gaXY7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogQ2lwaGVyIEJsb2NrIENoYWluaW5nIG1vZGUuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDQkMgPSBDX21vZGUuQ0JDID0gKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBBYnN0cmFjdCBiYXNlIENCQyBtb2RlLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHZhciBDQkMgPSBCbG9ja0NpcGhlck1vZGUuZXh0ZW5kKCk7XG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDQkMgZW5jcnlwdG9yLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIENCQy5FbmNyeXB0b3IgPSBDQkMuZXh0ZW5kKHtcblx0ICAgICAgICAgICAgLyoqXG5cdCAgICAgICAgICAgICAqIFByb2Nlc3NlcyB0aGUgZGF0YSBibG9jayBhdCBvZmZzZXQuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7QXJyYXl9IHdvcmRzIFRoZSBkYXRhIHdvcmRzIHRvIG9wZXJhdGUgb24uXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBvZmZzZXQgVGhlIG9mZnNldCB3aGVyZSB0aGUgYmxvY2sgc3RhcnRzLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgbW9kZS5wcm9jZXNzQmxvY2soZGF0YS53b3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgICovXG5cdCAgICAgICAgICAgIHByb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgdmFyIGNpcGhlciA9IHRoaXMuX2NpcGhlcjtcblx0ICAgICAgICAgICAgICAgIHZhciBibG9ja1NpemUgPSBjaXBoZXIuYmxvY2tTaXplO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBYT1IgYW5kIGVuY3J5cHRcblx0ICAgICAgICAgICAgICAgIHhvckJsb2NrLmNhbGwodGhpcywgd29yZHMsIG9mZnNldCwgYmxvY2tTaXplKTtcblx0ICAgICAgICAgICAgICAgIGNpcGhlci5lbmNyeXB0QmxvY2sod29yZHMsIG9mZnNldCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFJlbWVtYmVyIHRoaXMgYmxvY2sgdG8gdXNlIHdpdGggbmV4dCBibG9ja1xuXHQgICAgICAgICAgICAgICAgdGhpcy5fcHJldkJsb2NrID0gd29yZHMuc2xpY2Uob2Zmc2V0LCBvZmZzZXQgKyBibG9ja1NpemUpO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSk7XG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDQkMgZGVjcnlwdG9yLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIENCQy5EZWNyeXB0b3IgPSBDQkMuZXh0ZW5kKHtcblx0ICAgICAgICAgICAgLyoqXG5cdCAgICAgICAgICAgICAqIFByb2Nlc3NlcyB0aGUgZGF0YSBibG9jayBhdCBvZmZzZXQuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7QXJyYXl9IHdvcmRzIFRoZSBkYXRhIHdvcmRzIHRvIG9wZXJhdGUgb24uXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBvZmZzZXQgVGhlIG9mZnNldCB3aGVyZSB0aGUgYmxvY2sgc3RhcnRzLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgbW9kZS5wcm9jZXNzQmxvY2soZGF0YS53b3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgICovXG5cdCAgICAgICAgICAgIHByb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgdmFyIGNpcGhlciA9IHRoaXMuX2NpcGhlcjtcblx0ICAgICAgICAgICAgICAgIHZhciBibG9ja1NpemUgPSBjaXBoZXIuYmxvY2tTaXplO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBSZW1lbWJlciB0aGlzIGJsb2NrIHRvIHVzZSB3aXRoIG5leHQgYmxvY2tcblx0ICAgICAgICAgICAgICAgIHZhciB0aGlzQmxvY2sgPSB3b3Jkcy5zbGljZShvZmZzZXQsIG9mZnNldCArIGJsb2NrU2l6ZSk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIERlY3J5cHQgYW5kIFhPUlxuXHQgICAgICAgICAgICAgICAgY2lwaGVyLmRlY3J5cHRCbG9jayh3b3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgICAgIHhvckJsb2NrLmNhbGwodGhpcywgd29yZHMsIG9mZnNldCwgYmxvY2tTaXplKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gVGhpcyBibG9jayBiZWNvbWVzIHRoZSBwcmV2aW91cyBibG9ja1xuXHQgICAgICAgICAgICAgICAgdGhpcy5fcHJldkJsb2NrID0gdGhpc0Jsb2NrO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSk7XG5cblx0ICAgICAgICBmdW5jdGlvbiB4b3JCbG9jayh3b3Jkcywgb2Zmc2V0LCBibG9ja1NpemUpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGl2ID0gdGhpcy5faXY7XG5cblx0ICAgICAgICAgICAgLy8gQ2hvb3NlIG1peGluZyBibG9ja1xuXHQgICAgICAgICAgICBpZiAoaXYpIHtcblx0ICAgICAgICAgICAgICAgIHZhciBibG9jayA9IGl2O1xuXG5cdCAgICAgICAgICAgICAgICAvLyBSZW1vdmUgSVYgZm9yIHN1YnNlcXVlbnQgYmxvY2tzXG5cdCAgICAgICAgICAgICAgICB0aGlzLl9pdiA9IHVuZGVmaW5lZDtcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIHZhciBibG9jayA9IHRoaXMuX3ByZXZCbG9jaztcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFhPUiBibG9ja3Ncblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBibG9ja1NpemU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbb2Zmc2V0ICsgaV0gXj0gYmxvY2tbaV07XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cblx0ICAgICAgICByZXR1cm4gQ0JDO1xuXHQgICAgfSgpKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBQYWRkaW5nIG5hbWVzcGFjZS5cblx0ICAgICAqL1xuXHQgICAgdmFyIENfcGFkID0gQy5wYWQgPSB7fTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBQS0NTICM1LzcgcGFkZGluZyBzdHJhdGVneS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFBrY3M3ID0gQ19wYWQuUGtjczcgPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogUGFkcyBkYXRhIHVzaW5nIHRoZSBhbGdvcml0aG0gZGVmaW5lZCBpbiBQS0NTICM1LzcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gZGF0YSBUaGUgZGF0YSB0byBwYWQuXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IGJsb2NrU2l6ZSBUaGUgbXVsdGlwbGUgdGhhdCB0aGUgZGF0YSBzaG91bGQgYmUgcGFkZGVkIHRvLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBDcnlwdG9KUy5wYWQuUGtjczcucGFkKHdvcmRBcnJheSwgNCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcGFkOiBmdW5jdGlvbiAoZGF0YSwgYmxvY2tTaXplKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBibG9ja1NpemVCeXRlcyA9IGJsb2NrU2l6ZSAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gQ291bnQgcGFkZGluZyBieXRlc1xuXHQgICAgICAgICAgICB2YXIgblBhZGRpbmdCeXRlcyA9IGJsb2NrU2l6ZUJ5dGVzIC0gZGF0YS5zaWdCeXRlcyAlIGJsb2NrU2l6ZUJ5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIENyZWF0ZSBwYWRkaW5nIHdvcmRcblx0ICAgICAgICAgICAgdmFyIHBhZGRpbmdXb3JkID0gKG5QYWRkaW5nQnl0ZXMgPDwgMjQpIHwgKG5QYWRkaW5nQnl0ZXMgPDwgMTYpIHwgKG5QYWRkaW5nQnl0ZXMgPDwgOCkgfCBuUGFkZGluZ0J5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIENyZWF0ZSBwYWRkaW5nXG5cdCAgICAgICAgICAgIHZhciBwYWRkaW5nV29yZHMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBuUGFkZGluZ0J5dGVzOyBpICs9IDQpIHtcblx0ICAgICAgICAgICAgICAgIHBhZGRpbmdXb3Jkcy5wdXNoKHBhZGRpbmdXb3JkKTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB2YXIgcGFkZGluZyA9IFdvcmRBcnJheS5jcmVhdGUocGFkZGluZ1dvcmRzLCBuUGFkZGluZ0J5dGVzKTtcblxuXHQgICAgICAgICAgICAvLyBBZGQgcGFkZGluZ1xuXHQgICAgICAgICAgICBkYXRhLmNvbmNhdChwYWRkaW5nKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogVW5wYWRzIGRhdGEgdGhhdCBoYWQgYmVlbiBwYWRkZWQgdXNpbmcgdGhlIGFsZ29yaXRobSBkZWZpbmVkIGluIFBLQ1MgIzUvNy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSBkYXRhIFRoZSBkYXRhIHRvIHVucGFkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBDcnlwdG9KUy5wYWQuUGtjczcudW5wYWQod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICB1bnBhZDogZnVuY3Rpb24gKGRhdGEpIHtcblx0ICAgICAgICAgICAgLy8gR2V0IG51bWJlciBvZiBwYWRkaW5nIGJ5dGVzIGZyb20gbGFzdCBieXRlXG5cdCAgICAgICAgICAgIHZhciBuUGFkZGluZ0J5dGVzID0gZGF0YS53b3Jkc1soZGF0YS5zaWdCeXRlcyAtIDEpID4+PiAyXSAmIDB4ZmY7XG5cblx0ICAgICAgICAgICAgLy8gUmVtb3ZlIHBhZGRpbmdcblx0ICAgICAgICAgICAgZGF0YS5zaWdCeXRlcyAtPSBuUGFkZGluZ0J5dGVzO1xuXHQgICAgICAgIH1cblx0ICAgIH07XG5cblx0ICAgIC8qKlxuXHQgICAgICogQWJzdHJhY3QgYmFzZSBibG9jayBjaXBoZXIgdGVtcGxhdGUuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IGJsb2NrU2l6ZSBUaGUgbnVtYmVyIG9mIDMyLWJpdCB3b3JkcyB0aGlzIGNpcGhlciBvcGVyYXRlcyBvbi4gRGVmYXVsdDogNCAoMTI4IGJpdHMpXG5cdCAgICAgKi9cblx0ICAgIHZhciBCbG9ja0NpcGhlciA9IENfbGliLkJsb2NrQ2lwaGVyID0gQ2lwaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtNb2RlfSBtb2RlIFRoZSBibG9jayBtb2RlIHRvIHVzZS4gRGVmYXVsdDogQ0JDXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtQYWRkaW5nfSBwYWRkaW5nIFRoZSBwYWRkaW5nIHN0cmF0ZWd5IHRvIHVzZS4gRGVmYXVsdDogUGtjczdcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjZmc6IENpcGhlci5jZmcuZXh0ZW5kKHtcblx0ICAgICAgICAgICAgbW9kZTogQ0JDLFxuXHQgICAgICAgICAgICBwYWRkaW5nOiBQa2NzN1xuXHQgICAgICAgIH0pLFxuXG5cdCAgICAgICAgcmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gUmVzZXQgY2lwaGVyXG5cdCAgICAgICAgICAgIENpcGhlci5yZXNldC5jYWxsKHRoaXMpO1xuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgY2ZnID0gdGhpcy5jZmc7XG5cdCAgICAgICAgICAgIHZhciBpdiA9IGNmZy5pdjtcblx0ICAgICAgICAgICAgdmFyIG1vZGUgPSBjZmcubW9kZTtcblxuXHQgICAgICAgICAgICAvLyBSZXNldCBibG9jayBtb2RlXG5cdCAgICAgICAgICAgIGlmICh0aGlzLl94Zm9ybU1vZGUgPT0gdGhpcy5fRU5DX1hGT1JNX01PREUpIHtcblx0ICAgICAgICAgICAgICAgIHZhciBtb2RlQ3JlYXRvciA9IG1vZGUuY3JlYXRlRW5jcnlwdG9yO1xuXHQgICAgICAgICAgICB9IGVsc2UgLyogaWYgKHRoaXMuX3hmb3JtTW9kZSA9PSB0aGlzLl9ERUNfWEZPUk1fTU9ERSkgKi8ge1xuXHQgICAgICAgICAgICAgICAgdmFyIG1vZGVDcmVhdG9yID0gbW9kZS5jcmVhdGVEZWNyeXB0b3I7XG5cdCAgICAgICAgICAgICAgICAvLyBLZWVwIGF0IGxlYXN0IG9uZSBibG9jayBpbiB0aGUgYnVmZmVyIGZvciB1bnBhZGRpbmdcblx0ICAgICAgICAgICAgICAgIHRoaXMuX21pbkJ1ZmZlclNpemUgPSAxO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgaWYgKHRoaXMuX21vZGUgJiYgdGhpcy5fbW9kZS5fX2NyZWF0b3IgPT0gbW9kZUNyZWF0b3IpIHtcblx0ICAgICAgICAgICAgICAgIHRoaXMuX21vZGUuaW5pdCh0aGlzLCBpdiAmJiBpdi53b3Jkcyk7XG5cdCAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9tb2RlID0gbW9kZUNyZWF0b3IuY2FsbChtb2RlLCB0aGlzLCBpdiAmJiBpdi53b3Jkcyk7XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9tb2RlLl9fY3JlYXRvciA9IG1vZGVDcmVhdG9yO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgdGhpcy5fbW9kZS5wcm9jZXNzQmxvY2sod29yZHMsIG9mZnNldCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0ZpbmFsaXplOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBwYWRkaW5nID0gdGhpcy5jZmcucGFkZGluZztcblxuXHQgICAgICAgICAgICAvLyBGaW5hbGl6ZVxuXHQgICAgICAgICAgICBpZiAodGhpcy5feGZvcm1Nb2RlID09IHRoaXMuX0VOQ19YRk9STV9NT0RFKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBQYWQgZGF0YVxuXHQgICAgICAgICAgICAgICAgcGFkZGluZy5wYWQodGhpcy5fZGF0YSwgdGhpcy5ibG9ja1NpemUpO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBQcm9jZXNzIGZpbmFsIGJsb2Nrc1xuXHQgICAgICAgICAgICAgICAgdmFyIGZpbmFsUHJvY2Vzc2VkQmxvY2tzID0gdGhpcy5fcHJvY2VzcyghISdmbHVzaCcpO1xuXHQgICAgICAgICAgICB9IGVsc2UgLyogaWYgKHRoaXMuX3hmb3JtTW9kZSA9PSB0aGlzLl9ERUNfWEZPUk1fTU9ERSkgKi8ge1xuXHQgICAgICAgICAgICAgICAgLy8gUHJvY2VzcyBmaW5hbCBibG9ja3Ncblx0ICAgICAgICAgICAgICAgIHZhciBmaW5hbFByb2Nlc3NlZEJsb2NrcyA9IHRoaXMuX3Byb2Nlc3MoISEnZmx1c2gnKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gVW5wYWQgZGF0YVxuXHQgICAgICAgICAgICAgICAgcGFkZGluZy51bnBhZChmaW5hbFByb2Nlc3NlZEJsb2Nrcyk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gZmluYWxQcm9jZXNzZWRCbG9ja3M7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGJsb2NrU2l6ZTogMTI4LzMyXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBIGNvbGxlY3Rpb24gb2YgY2lwaGVyIHBhcmFtZXRlcnMuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtXb3JkQXJyYXl9IGNpcGhlcnRleHQgVGhlIHJhdyBjaXBoZXJ0ZXh0LlxuXHQgICAgICogQHByb3BlcnR5IHtXb3JkQXJyYXl9IGtleSBUaGUga2V5IHRvIHRoaXMgY2lwaGVydGV4dC5cblx0ICAgICAqIEBwcm9wZXJ0eSB7V29yZEFycmF5fSBpdiBUaGUgSVYgdXNlZCBpbiB0aGUgY2lwaGVyaW5nIG9wZXJhdGlvbi5cblx0ICAgICAqIEBwcm9wZXJ0eSB7V29yZEFycmF5fSBzYWx0IFRoZSBzYWx0IHVzZWQgd2l0aCBhIGtleSBkZXJpdmF0aW9uIGZ1bmN0aW9uLlxuXHQgICAgICogQHByb3BlcnR5IHtDaXBoZXJ9IGFsZ29yaXRobSBUaGUgY2lwaGVyIGFsZ29yaXRobS5cblx0ICAgICAqIEBwcm9wZXJ0eSB7TW9kZX0gbW9kZSBUaGUgYmxvY2sgbW9kZSB1c2VkIGluIHRoZSBjaXBoZXJpbmcgb3BlcmF0aW9uLlxuXHQgICAgICogQHByb3BlcnR5IHtQYWRkaW5nfSBwYWRkaW5nIFRoZSBwYWRkaW5nIHNjaGVtZSB1c2VkIGluIHRoZSBjaXBoZXJpbmcgb3BlcmF0aW9uLlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IGJsb2NrU2l6ZSBUaGUgYmxvY2sgc2l6ZSBvZiB0aGUgY2lwaGVyLlxuXHQgICAgICogQHByb3BlcnR5IHtGb3JtYXR9IGZvcm1hdHRlciBUaGUgZGVmYXVsdCBmb3JtYXR0aW5nIHN0cmF0ZWd5IHRvIGNvbnZlcnQgdGhpcyBjaXBoZXIgcGFyYW1zIG9iamVjdCB0byBhIHN0cmluZy5cblx0ICAgICAqL1xuXHQgICAgdmFyIENpcGhlclBhcmFtcyA9IENfbGliLkNpcGhlclBhcmFtcyA9IEJhc2UuZXh0ZW5kKHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2lwaGVyUGFyYW1zIEFuIG9iamVjdCB3aXRoIGFueSBvZiB0aGUgcG9zc2libGUgY2lwaGVyIHBhcmFtZXRlcnMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjaXBoZXJQYXJhbXMgPSBDcnlwdG9KUy5saWIuQ2lwaGVyUGFyYW1zLmNyZWF0ZSh7XG5cdCAgICAgICAgICogICAgICAgICBjaXBoZXJ0ZXh0OiBjaXBoZXJ0ZXh0V29yZEFycmF5LFxuXHQgICAgICAgICAqICAgICAgICAga2V5OiBrZXlXb3JkQXJyYXksXG5cdCAgICAgICAgICogICAgICAgICBpdjogaXZXb3JkQXJyYXksXG5cdCAgICAgICAgICogICAgICAgICBzYWx0OiBzYWx0V29yZEFycmF5LFxuXHQgICAgICAgICAqICAgICAgICAgYWxnb3JpdGhtOiBDcnlwdG9KUy5hbGdvLkFFUyxcblx0ICAgICAgICAgKiAgICAgICAgIG1vZGU6IENyeXB0b0pTLm1vZGUuQ0JDLFxuXHQgICAgICAgICAqICAgICAgICAgcGFkZGluZzogQ3J5cHRvSlMucGFkLlBLQ1M3LFxuXHQgICAgICAgICAqICAgICAgICAgYmxvY2tTaXplOiA0LFxuXHQgICAgICAgICAqICAgICAgICAgZm9ybWF0dGVyOiBDcnlwdG9KUy5mb3JtYXQuT3BlblNTTFxuXHQgICAgICAgICAqICAgICB9KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoY2lwaGVyUGFyYW1zKSB7XG5cdCAgICAgICAgICAgIHRoaXMubWl4SW4oY2lwaGVyUGFyYW1zKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgdGhpcyBjaXBoZXIgcGFyYW1zIG9iamVjdCB0byBhIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Rm9ybWF0fSBmb3JtYXR0ZXIgKE9wdGlvbmFsKSBUaGUgZm9ybWF0dGluZyBzdHJhdGVneSB0byB1c2UuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBzdHJpbmdpZmllZCBjaXBoZXIgcGFyYW1zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHRocm93cyBFcnJvciBJZiBuZWl0aGVyIHRoZSBmb3JtYXR0ZXIgbm9yIHRoZSBkZWZhdWx0IGZvcm1hdHRlciBpcyBzZXQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBzdHJpbmcgPSBjaXBoZXJQYXJhbXMgKyAnJztcblx0ICAgICAgICAgKiAgICAgdmFyIHN0cmluZyA9IGNpcGhlclBhcmFtcy50b1N0cmluZygpO1xuXHQgICAgICAgICAqICAgICB2YXIgc3RyaW5nID0gY2lwaGVyUGFyYW1zLnRvU3RyaW5nKENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICB0b1N0cmluZzogZnVuY3Rpb24gKGZvcm1hdHRlcikge1xuXHQgICAgICAgICAgICByZXR1cm4gKGZvcm1hdHRlciB8fCB0aGlzLmZvcm1hdHRlcikuc3RyaW5naWZ5KHRoaXMpO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEZvcm1hdCBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX2Zvcm1hdCA9IEMuZm9ybWF0ID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogT3BlblNTTCBmb3JtYXR0aW5nIHN0cmF0ZWd5LlxuXHQgICAgICovXG5cdCAgICB2YXIgT3BlblNTTEZvcm1hdHRlciA9IENfZm9ybWF0Lk9wZW5TU0wgPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBjaXBoZXIgcGFyYW1zIG9iamVjdCB0byBhbiBPcGVuU1NMLWNvbXBhdGlibGUgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJQYXJhbXN9IGNpcGhlclBhcmFtcyBUaGUgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBPcGVuU1NMLWNvbXBhdGlibGUgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgb3BlblNTTFN0cmluZyA9IENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMLnN0cmluZ2lmeShjaXBoZXJQYXJhbXMpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHN0cmluZ2lmeTogZnVuY3Rpb24gKGNpcGhlclBhcmFtcykge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGNpcGhlcnRleHQgPSBjaXBoZXJQYXJhbXMuY2lwaGVydGV4dDtcblx0ICAgICAgICAgICAgdmFyIHNhbHQgPSBjaXBoZXJQYXJhbXMuc2FsdDtcblxuXHQgICAgICAgICAgICAvLyBGb3JtYXRcblx0ICAgICAgICAgICAgaWYgKHNhbHQpIHtcblx0ICAgICAgICAgICAgICAgIHZhciB3b3JkQXJyYXkgPSBXb3JkQXJyYXkuY3JlYXRlKFsweDUzNjE2Yzc0LCAweDY1NjQ1ZjVmXSkuY29uY2F0KHNhbHQpLmNvbmNhdChjaXBoZXJ0ZXh0KTtcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIHZhciB3b3JkQXJyYXkgPSBjaXBoZXJ0ZXh0O1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIHdvcmRBcnJheS50b1N0cmluZyhCYXNlNjQpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBhbiBPcGVuU1NMLWNvbXBhdGlibGUgc3RyaW5nIHRvIGEgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gb3BlblNTTFN0ciBUaGUgT3BlblNTTC1jb21wYXRpYmxlIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0NpcGhlclBhcmFtc30gVGhlIGNpcGhlciBwYXJhbXMgb2JqZWN0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVyUGFyYW1zID0gQ3J5cHRvSlMuZm9ybWF0Lk9wZW5TU0wucGFyc2Uob3BlblNTTFN0cmluZyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcGFyc2U6IGZ1bmN0aW9uIChvcGVuU1NMU3RyKSB7XG5cdCAgICAgICAgICAgIC8vIFBhcnNlIGJhc2U2NFxuXHQgICAgICAgICAgICB2YXIgY2lwaGVydGV4dCA9IEJhc2U2NC5wYXJzZShvcGVuU1NMU3RyKTtcblxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgY2lwaGVydGV4dFdvcmRzID0gY2lwaGVydGV4dC53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBUZXN0IGZvciBzYWx0XG5cdCAgICAgICAgICAgIGlmIChjaXBoZXJ0ZXh0V29yZHNbMF0gPT0gMHg1MzYxNmM3NCAmJiBjaXBoZXJ0ZXh0V29yZHNbMV0gPT0gMHg2NTY0NWY1Zikge1xuXHQgICAgICAgICAgICAgICAgLy8gRXh0cmFjdCBzYWx0XG5cdCAgICAgICAgICAgICAgICB2YXIgc2FsdCA9IFdvcmRBcnJheS5jcmVhdGUoY2lwaGVydGV4dFdvcmRzLnNsaWNlKDIsIDQpKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIHNhbHQgZnJvbSBjaXBoZXJ0ZXh0XG5cdCAgICAgICAgICAgICAgICBjaXBoZXJ0ZXh0V29yZHMuc3BsaWNlKDAsIDQpO1xuXHQgICAgICAgICAgICAgICAgY2lwaGVydGV4dC5zaWdCeXRlcyAtPSAxNjtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBDaXBoZXJQYXJhbXMuY3JlYXRlKHsgY2lwaGVydGV4dDogY2lwaGVydGV4dCwgc2FsdDogc2FsdCB9KTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEEgY2lwaGVyIHdyYXBwZXIgdGhhdCByZXR1cm5zIGNpcGhlcnRleHQgYXMgYSBzZXJpYWxpemFibGUgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgKi9cblx0ICAgIHZhciBTZXJpYWxpemFibGVDaXBoZXIgPSBDX2xpYi5TZXJpYWxpemFibGVDaXBoZXIgPSBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtGb3JtYXR0ZXJ9IGZvcm1hdCBUaGUgZm9ybWF0dGluZyBzdHJhdGVneSB0byBjb252ZXJ0IGNpcGhlciBwYXJhbSBvYmplY3RzIHRvIGFuZCBmcm9tIGEgc3RyaW5nLiBEZWZhdWx0OiBPcGVuU1NMXG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2ZnOiBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgICAgIGZvcm1hdDogT3BlblNTTEZvcm1hdHRlclxuXHQgICAgICAgIH0pLFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogRW5jcnlwdHMgYSBtZXNzYWdlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBUaGUgY2lwaGVyIGFsZ29yaXRobSB0byB1c2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGVuY3J5cHQuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGtleSBUaGUga2V5LlxuXHQgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJQYXJhbXN9IEEgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0UGFyYW1zID0gQ3J5cHRvSlMubGliLlNlcmlhbGl6YWJsZUNpcGhlci5lbmNyeXB0KENyeXB0b0pTLmFsZ28uQUVTLCBtZXNzYWdlLCBrZXkpO1xuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVydGV4dFBhcmFtcyA9IENyeXB0b0pTLmxpYi5TZXJpYWxpemFibGVDaXBoZXIuZW5jcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgbWVzc2FnZSwga2V5LCB7IGl2OiBpdiB9KTtcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlcnRleHRQYXJhbXMgPSBDcnlwdG9KUy5saWIuU2VyaWFsaXphYmxlQ2lwaGVyLmVuY3J5cHQoQ3J5cHRvSlMuYWxnby5BRVMsIG1lc3NhZ2UsIGtleSwgeyBpdjogaXYsIGZvcm1hdDogQ3J5cHRvSlMuZm9ybWF0Lk9wZW5TU0wgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgZW5jcnlwdDogZnVuY3Rpb24gKGNpcGhlciwgbWVzc2FnZSwga2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIGNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXG5cdCAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgdmFyIGVuY3J5cHRvciA9IGNpcGhlci5jcmVhdGVFbmNyeXB0b3Ioa2V5LCBjZmcpO1xuXHQgICAgICAgICAgICB2YXIgY2lwaGVydGV4dCA9IGVuY3J5cHRvci5maW5hbGl6ZShtZXNzYWdlKTtcblxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgY2lwaGVyQ2ZnID0gZW5jcnlwdG9yLmNmZztcblxuXHQgICAgICAgICAgICAvLyBDcmVhdGUgYW5kIHJldHVybiBzZXJpYWxpemFibGUgY2lwaGVyIHBhcmFtc1xuXHQgICAgICAgICAgICByZXR1cm4gQ2lwaGVyUGFyYW1zLmNyZWF0ZSh7XG5cdCAgICAgICAgICAgICAgICBjaXBoZXJ0ZXh0OiBjaXBoZXJ0ZXh0LFxuXHQgICAgICAgICAgICAgICAga2V5OiBrZXksXG5cdCAgICAgICAgICAgICAgICBpdjogY2lwaGVyQ2ZnLml2LFxuXHQgICAgICAgICAgICAgICAgYWxnb3JpdGhtOiBjaXBoZXIsXG5cdCAgICAgICAgICAgICAgICBtb2RlOiBjaXBoZXJDZmcubW9kZSxcblx0ICAgICAgICAgICAgICAgIHBhZGRpbmc6IGNpcGhlckNmZy5wYWRkaW5nLFxuXHQgICAgICAgICAgICAgICAgYmxvY2tTaXplOiBjaXBoZXIuYmxvY2tTaXplLFxuXHQgICAgICAgICAgICAgICAgZm9ybWF0dGVyOiBjZmcuZm9ybWF0XG5cdCAgICAgICAgICAgIH0pO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBEZWNyeXB0cyBzZXJpYWxpemVkIGNpcGhlcnRleHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0NpcGhlcn0gY2lwaGVyIFRoZSBjaXBoZXIgYWxnb3JpdGhtIHRvIHVzZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge0NpcGhlclBhcmFtc3xzdHJpbmd9IGNpcGhlcnRleHQgVGhlIGNpcGhlcnRleHQgdG8gZGVjcnlwdC5cblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0ga2V5IFRoZSBrZXkuXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHBsYWludGV4dC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHBsYWludGV4dCA9IENyeXB0b0pTLmxpYi5TZXJpYWxpemFibGVDaXBoZXIuZGVjcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgZm9ybWF0dGVkQ2lwaGVydGV4dCwga2V5LCB7IGl2OiBpdiwgZm9ybWF0OiBDcnlwdG9KUy5mb3JtYXQuT3BlblNTTCB9KTtcblx0ICAgICAgICAgKiAgICAgdmFyIHBsYWludGV4dCA9IENyeXB0b0pTLmxpYi5TZXJpYWxpemFibGVDaXBoZXIuZGVjcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgY2lwaGVydGV4dFBhcmFtcywga2V5LCB7IGl2OiBpdiwgZm9ybWF0OiBDcnlwdG9KUy5mb3JtYXQuT3BlblNTTCB9KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBkZWNyeXB0OiBmdW5jdGlvbiAoY2lwaGVyLCBjaXBoZXJ0ZXh0LCBrZXksIGNmZykge1xuXHQgICAgICAgICAgICAvLyBBcHBseSBjb25maWcgZGVmYXVsdHNcblx0ICAgICAgICAgICAgY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydCBzdHJpbmcgdG8gQ2lwaGVyUGFyYW1zXG5cdCAgICAgICAgICAgIGNpcGhlcnRleHQgPSB0aGlzLl9wYXJzZShjaXBoZXJ0ZXh0LCBjZmcuZm9ybWF0KTtcblxuXHQgICAgICAgICAgICAvLyBEZWNyeXB0XG5cdCAgICAgICAgICAgIHZhciBwbGFpbnRleHQgPSBjaXBoZXIuY3JlYXRlRGVjcnlwdG9yKGtleSwgY2ZnKS5maW5hbGl6ZShjaXBoZXJ0ZXh0LmNpcGhlcnRleHQpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBwbGFpbnRleHQ7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIHNlcmlhbGl6ZWQgY2lwaGVydGV4dCB0byBDaXBoZXJQYXJhbXMsXG5cdCAgICAgICAgICogZWxzZSBhc3N1bWVkIENpcGhlclBhcmFtcyBhbHJlYWR5IGFuZCByZXR1cm5zIGNpcGhlcnRleHQgdW5jaGFuZ2VkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJQYXJhbXN8c3RyaW5nfSBjaXBoZXJ0ZXh0IFRoZSBjaXBoZXJ0ZXh0LlxuXHQgICAgICAgICAqIEBwYXJhbSB7Rm9ybWF0dGVyfSBmb3JtYXQgVGhlIGZvcm1hdHRpbmcgc3RyYXRlZ3kgdG8gdXNlIHRvIHBhcnNlIHNlcmlhbGl6ZWQgY2lwaGVydGV4dC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0NpcGhlclBhcmFtc30gVGhlIHVuc2VyaWFsaXplZCBjaXBoZXJ0ZXh0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVydGV4dFBhcmFtcyA9IENyeXB0b0pTLmxpYi5TZXJpYWxpemFibGVDaXBoZXIuX3BhcnNlKGNpcGhlcnRleHRTdHJpbmdPclBhcmFtcywgZm9ybWF0KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBfcGFyc2U6IGZ1bmN0aW9uIChjaXBoZXJ0ZXh0LCBmb3JtYXQpIHtcblx0ICAgICAgICAgICAgaWYgKHR5cGVvZiBjaXBoZXJ0ZXh0ID09ICdzdHJpbmcnKSB7XG5cdCAgICAgICAgICAgICAgICByZXR1cm4gZm9ybWF0LnBhcnNlKGNpcGhlcnRleHQsIHRoaXMpO1xuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgcmV0dXJuIGNpcGhlcnRleHQ7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBLZXkgZGVyaXZhdGlvbiBmdW5jdGlvbiBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX2tkZiA9IEMua2RmID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogT3BlblNTTCBrZXkgZGVyaXZhdGlvbiBmdW5jdGlvbi5cblx0ICAgICAqL1xuXHQgICAgdmFyIE9wZW5TU0xLZGYgPSBDX2tkZi5PcGVuU1NMID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIERlcml2ZXMgYSBrZXkgYW5kIElWIGZyb20gYSBwYXNzd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQgdG8gZGVyaXZlIGZyb20uXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IGtleVNpemUgVGhlIHNpemUgaW4gd29yZHMgb2YgdGhlIGtleSB0byBnZW5lcmF0ZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0gaXZTaXplIFRoZSBzaXplIGluIHdvcmRzIG9mIHRoZSBJViB0byBnZW5lcmF0ZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IHNhbHQgKE9wdGlvbmFsKSBBIDY0LWJpdCBzYWx0IHRvIHVzZS4gSWYgb21pdHRlZCwgYSBzYWx0IHdpbGwgYmUgZ2VuZXJhdGVkIHJhbmRvbWx5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7Q2lwaGVyUGFyYW1zfSBBIGNpcGhlciBwYXJhbXMgb2JqZWN0IHdpdGggdGhlIGtleSwgSVYsIGFuZCBzYWx0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgZGVyaXZlZFBhcmFtcyA9IENyeXB0b0pTLmtkZi5PcGVuU1NMLmV4ZWN1dGUoJ1Bhc3N3b3JkJywgMjU2LzMyLCAxMjgvMzIpO1xuXHQgICAgICAgICAqICAgICB2YXIgZGVyaXZlZFBhcmFtcyA9IENyeXB0b0pTLmtkZi5PcGVuU1NMLmV4ZWN1dGUoJ1Bhc3N3b3JkJywgMjU2LzMyLCAxMjgvMzIsICdzYWx0c2FsdCcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGV4ZWN1dGU6IGZ1bmN0aW9uIChwYXNzd29yZCwga2V5U2l6ZSwgaXZTaXplLCBzYWx0KSB7XG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIHJhbmRvbSBzYWx0XG5cdCAgICAgICAgICAgIGlmICghc2FsdCkge1xuXHQgICAgICAgICAgICAgICAgc2FsdCA9IFdvcmRBcnJheS5yYW5kb20oNjQvOCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBEZXJpdmUga2V5IGFuZCBJVlxuXHQgICAgICAgICAgICB2YXIga2V5ID0gRXZwS0RGLmNyZWF0ZSh7IGtleVNpemU6IGtleVNpemUgKyBpdlNpemUgfSkuY29tcHV0ZShwYXNzd29yZCwgc2FsdCk7XG5cblx0ICAgICAgICAgICAgLy8gU2VwYXJhdGUga2V5IGFuZCBJVlxuXHQgICAgICAgICAgICB2YXIgaXYgPSBXb3JkQXJyYXkuY3JlYXRlKGtleS53b3Jkcy5zbGljZShrZXlTaXplKSwgaXZTaXplICogNCk7XG5cdCAgICAgICAgICAgIGtleS5zaWdCeXRlcyA9IGtleVNpemUgKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIFJldHVybiBwYXJhbXNcblx0ICAgICAgICAgICAgcmV0dXJuIENpcGhlclBhcmFtcy5jcmVhdGUoeyBrZXk6IGtleSwgaXY6IGl2LCBzYWx0OiBzYWx0IH0pO1xuXHQgICAgICAgIH1cblx0ICAgIH07XG5cblx0ICAgIC8qKlxuXHQgICAgICogQSBzZXJpYWxpemFibGUgY2lwaGVyIHdyYXBwZXIgdGhhdCBkZXJpdmVzIHRoZSBrZXkgZnJvbSBhIHBhc3N3b3JkLFxuXHQgICAgICogYW5kIHJldHVybnMgY2lwaGVydGV4dCBhcyBhIHNlcmlhbGl6YWJsZSBjaXBoZXIgcGFyYW1zIG9iamVjdC5cblx0ICAgICAqL1xuXHQgICAgdmFyIFBhc3N3b3JkQmFzZWRDaXBoZXIgPSBDX2xpYi5QYXNzd29yZEJhc2VkQ2lwaGVyID0gU2VyaWFsaXphYmxlQ2lwaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtLREZ9IGtkZiBUaGUga2V5IGRlcml2YXRpb24gZnVuY3Rpb24gdG8gdXNlIHRvIGdlbmVyYXRlIGEga2V5IGFuZCBJViBmcm9tIGEgcGFzc3dvcmQuIERlZmF1bHQ6IE9wZW5TU0xcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjZmc6IFNlcmlhbGl6YWJsZUNpcGhlci5jZmcuZXh0ZW5kKHtcblx0ICAgICAgICAgICAga2RmOiBPcGVuU1NMS2RmXG5cdCAgICAgICAgfSksXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBFbmNyeXB0cyBhIG1lc3NhZ2UgdXNpbmcgYSBwYXNzd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyfSBjaXBoZXIgVGhlIGNpcGhlciBhbGdvcml0aG0gdG8gdXNlLlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBlbmNyeXB0LlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQuXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0NpcGhlclBhcmFtc30gQSBjaXBoZXIgcGFyYW1zIG9iamVjdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlcnRleHRQYXJhbXMgPSBDcnlwdG9KUy5saWIuUGFzc3dvcmRCYXNlZENpcGhlci5lbmNyeXB0KENyeXB0b0pTLmFsZ28uQUVTLCBtZXNzYWdlLCAncGFzc3dvcmQnKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlcnRleHRQYXJhbXMgPSBDcnlwdG9KUy5saWIuUGFzc3dvcmRCYXNlZENpcGhlci5lbmNyeXB0KENyeXB0b0pTLmFsZ28uQUVTLCBtZXNzYWdlLCAncGFzc3dvcmQnLCB7IGZvcm1hdDogQ3J5cHRvSlMuZm9ybWF0Lk9wZW5TU0wgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgZW5jcnlwdDogZnVuY3Rpb24gKGNpcGhlciwgbWVzc2FnZSwgcGFzc3dvcmQsIGNmZykge1xuXHQgICAgICAgICAgICAvLyBBcHBseSBjb25maWcgZGVmYXVsdHNcblx0ICAgICAgICAgICAgY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gRGVyaXZlIGtleSBhbmQgb3RoZXIgcGFyYW1zXG5cdCAgICAgICAgICAgIHZhciBkZXJpdmVkUGFyYW1zID0gY2ZnLmtkZi5leGVjdXRlKHBhc3N3b3JkLCBjaXBoZXIua2V5U2l6ZSwgY2lwaGVyLml2U2l6ZSk7XG5cblx0ICAgICAgICAgICAgLy8gQWRkIElWIHRvIGNvbmZpZ1xuXHQgICAgICAgICAgICBjZmcuaXYgPSBkZXJpdmVkUGFyYW1zLml2O1xuXG5cdCAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgdmFyIGNpcGhlcnRleHQgPSBTZXJpYWxpemFibGVDaXBoZXIuZW5jcnlwdC5jYWxsKHRoaXMsIGNpcGhlciwgbWVzc2FnZSwgZGVyaXZlZFBhcmFtcy5rZXksIGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gTWl4IGluIGRlcml2ZWQgcGFyYW1zXG5cdCAgICAgICAgICAgIGNpcGhlcnRleHQubWl4SW4oZGVyaXZlZFBhcmFtcyk7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGNpcGhlcnRleHQ7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIERlY3J5cHRzIHNlcmlhbGl6ZWQgY2lwaGVydGV4dCB1c2luZyBhIHBhc3N3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBUaGUgY2lwaGVyIGFsZ29yaXRobSB0byB1c2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJQYXJhbXN8c3RyaW5nfSBjaXBoZXJ0ZXh0IFRoZSBjaXBoZXJ0ZXh0IHRvIGRlY3J5cHQuXG5cdCAgICAgICAgICogQHBhcmFtIHtzdHJpbmd9IHBhc3N3b3JkIFRoZSBwYXNzd29yZC5cblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoaXMgb3BlcmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgcGxhaW50ZXh0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgcGxhaW50ZXh0ID0gQ3J5cHRvSlMubGliLlBhc3N3b3JkQmFzZWRDaXBoZXIuZGVjcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgZm9ybWF0dGVkQ2lwaGVydGV4dCwgJ3Bhc3N3b3JkJywgeyBmb3JtYXQ6IENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMIH0pO1xuXHQgICAgICAgICAqICAgICB2YXIgcGxhaW50ZXh0ID0gQ3J5cHRvSlMubGliLlBhc3N3b3JkQmFzZWRDaXBoZXIuZGVjcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgY2lwaGVydGV4dFBhcmFtcywgJ3Bhc3N3b3JkJywgeyBmb3JtYXQ6IENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMIH0pO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGRlY3J5cHQ6IGZ1bmN0aW9uIChjaXBoZXIsIGNpcGhlcnRleHQsIHBhc3N3b3JkLCBjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIGNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnQgc3RyaW5nIHRvIENpcGhlclBhcmFtc1xuXHQgICAgICAgICAgICBjaXBoZXJ0ZXh0ID0gdGhpcy5fcGFyc2UoY2lwaGVydGV4dCwgY2ZnLmZvcm1hdCk7XG5cblx0ICAgICAgICAgICAgLy8gRGVyaXZlIGtleSBhbmQgb3RoZXIgcGFyYW1zXG5cdCAgICAgICAgICAgIHZhciBkZXJpdmVkUGFyYW1zID0gY2ZnLmtkZi5leGVjdXRlKHBhc3N3b3JkLCBjaXBoZXIua2V5U2l6ZSwgY2lwaGVyLml2U2l6ZSwgY2lwaGVydGV4dC5zYWx0KTtcblxuXHQgICAgICAgICAgICAvLyBBZGQgSVYgdG8gY29uZmlnXG5cdCAgICAgICAgICAgIGNmZy5pdiA9IGRlcml2ZWRQYXJhbXMuaXY7XG5cblx0ICAgICAgICAgICAgLy8gRGVjcnlwdFxuXHQgICAgICAgICAgICB2YXIgcGxhaW50ZXh0ID0gU2VyaWFsaXphYmxlQ2lwaGVyLmRlY3J5cHQuY2FsbCh0aGlzLCBjaXBoZXIsIGNpcGhlcnRleHQsIGRlcml2ZWRQYXJhbXMua2V5LCBjZmcpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBwbGFpbnRleHQ7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cdH0oKSk7XG5cblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KCk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW10sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRyb290LkNyeXB0b0pTID0gZmFjdG9yeSgpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uICgpIHtcblxuXHQvKipcblx0ICogQ3J5cHRvSlMgY29yZSBjb21wb25lbnRzLlxuXHQgKi9cblx0dmFyIENyeXB0b0pTID0gQ3J5cHRvSlMgfHwgKGZ1bmN0aW9uIChNYXRoLCB1bmRlZmluZWQpIHtcblx0ICAgIC8qXG5cdCAgICAgKiBMb2NhbCBwb2x5ZmlsIG9mIE9iamVjdC5jcmVhdGVcblx0ICAgICAqL1xuXHQgICAgdmFyIGNyZWF0ZSA9IE9iamVjdC5jcmVhdGUgfHwgKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICBmdW5jdGlvbiBGKCkge307XG5cblx0ICAgICAgICByZXR1cm4gZnVuY3Rpb24gKG9iaikge1xuXHQgICAgICAgICAgICB2YXIgc3VidHlwZTtcblxuXHQgICAgICAgICAgICBGLnByb3RvdHlwZSA9IG9iajtcblxuXHQgICAgICAgICAgICBzdWJ0eXBlID0gbmV3IEYoKTtcblxuXHQgICAgICAgICAgICBGLnByb3RvdHlwZSA9IG51bGw7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIHN1YnR5cGU7XG5cdCAgICAgICAgfTtcblx0ICAgIH0oKSlcblxuXHQgICAgLyoqXG5cdCAgICAgKiBDcnlwdG9KUyBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogTGlicmFyeSBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX2xpYiA9IEMubGliID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogQmFzZSBvYmplY3QgZm9yIHByb3RvdHlwYWwgaW5oZXJpdGFuY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBCYXNlID0gQ19saWIuQmFzZSA9IChmdW5jdGlvbiAoKSB7XG5cblxuXHQgICAgICAgIHJldHVybiB7XG5cdCAgICAgICAgICAgIC8qKlxuXHQgICAgICAgICAgICAgKiBDcmVhdGVzIGEgbmV3IG9iamVjdCB0aGF0IGluaGVyaXRzIGZyb20gdGhpcyBvYmplY3QuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBvdmVycmlkZXMgUHJvcGVydGllcyB0byBjb3B5IGludG8gdGhlIG5ldyBvYmplY3QuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEByZXR1cm4ge09iamVjdH0gVGhlIG5ldyBvYmplY3QuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogICAgIHZhciBNeVR5cGUgPSBDcnlwdG9KUy5saWIuQmFzZS5leHRlbmQoe1xuXHQgICAgICAgICAgICAgKiAgICAgICAgIGZpZWxkOiAndmFsdWUnLFxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgICAgIG1ldGhvZDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAgKiAgICAgICAgIH1cblx0ICAgICAgICAgICAgICogICAgIH0pO1xuXHQgICAgICAgICAgICAgKi9cblx0ICAgICAgICAgICAgZXh0ZW5kOiBmdW5jdGlvbiAob3ZlcnJpZGVzKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTcGF3blxuXHQgICAgICAgICAgICAgICAgdmFyIHN1YnR5cGUgPSBjcmVhdGUodGhpcyk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIEF1Z21lbnRcblx0ICAgICAgICAgICAgICAgIGlmIChvdmVycmlkZXMpIHtcblx0ICAgICAgICAgICAgICAgICAgICBzdWJ0eXBlLm1peEluKG92ZXJyaWRlcyk7XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIC8vIENyZWF0ZSBkZWZhdWx0IGluaXRpYWxpemVyXG5cdCAgICAgICAgICAgICAgICBpZiAoIXN1YnR5cGUuaGFzT3duUHJvcGVydHkoJ2luaXQnKSB8fCB0aGlzLmluaXQgPT09IHN1YnR5cGUuaW5pdCkge1xuXHQgICAgICAgICAgICAgICAgICAgIHN1YnR5cGUuaW5pdCA9IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgc3VidHlwZS4kc3VwZXIuaW5pdC5hcHBseSh0aGlzLCBhcmd1bWVudHMpO1xuXHQgICAgICAgICAgICAgICAgICAgIH07XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIC8vIEluaXRpYWxpemVyJ3MgcHJvdG90eXBlIGlzIHRoZSBzdWJ0eXBlIG9iamVjdFxuXHQgICAgICAgICAgICAgICAgc3VidHlwZS5pbml0LnByb3RvdHlwZSA9IHN1YnR5cGU7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFJlZmVyZW5jZSBzdXBlcnR5cGVcblx0ICAgICAgICAgICAgICAgIHN1YnR5cGUuJHN1cGVyID0gdGhpcztcblxuXHQgICAgICAgICAgICAgICAgcmV0dXJuIHN1YnR5cGU7XG5cdCAgICAgICAgICAgIH0sXG5cblx0ICAgICAgICAgICAgLyoqXG5cdCAgICAgICAgICAgICAqIEV4dGVuZHMgdGhpcyBvYmplY3QgYW5kIHJ1bnMgdGhlIGluaXQgbWV0aG9kLlxuXHQgICAgICAgICAgICAgKiBBcmd1bWVudHMgdG8gY3JlYXRlKCkgd2lsbCBiZSBwYXNzZWQgdG8gaW5pdCgpLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAcmV0dXJuIHtPYmplY3R9IFRoZSBuZXcgb2JqZWN0LlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqICAgICB2YXIgaW5zdGFuY2UgPSBNeVR5cGUuY3JlYXRlKCk7XG5cdCAgICAgICAgICAgICAqL1xuXHQgICAgICAgICAgICBjcmVhdGU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgICAgIHZhciBpbnN0YW5jZSA9IHRoaXMuZXh0ZW5kKCk7XG5cdCAgICAgICAgICAgICAgICBpbnN0YW5jZS5pbml0LmFwcGx5KGluc3RhbmNlLCBhcmd1bWVudHMpO1xuXG5cdCAgICAgICAgICAgICAgICByZXR1cm4gaW5zdGFuY2U7XG5cdCAgICAgICAgICAgIH0sXG5cblx0ICAgICAgICAgICAgLyoqXG5cdCAgICAgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCBvYmplY3QuXG5cdCAgICAgICAgICAgICAqIE92ZXJyaWRlIHRoaXMgbWV0aG9kIHRvIGFkZCBzb21lIGxvZ2ljIHdoZW4geW91ciBvYmplY3RzIGFyZSBjcmVhdGVkLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgdmFyIE15VHlwZSA9IENyeXB0b0pTLmxpYi5CYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgICAgICAqICAgICAgICAgaW5pdDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAgKiAgICAgICAgICAgICAvLyAuLi5cblx0ICAgICAgICAgICAgICogICAgICAgICB9XG5cdCAgICAgICAgICAgICAqICAgICB9KTtcblx0ICAgICAgICAgICAgICovXG5cdCAgICAgICAgICAgIGluaXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgfSxcblxuXHQgICAgICAgICAgICAvKipcblx0ICAgICAgICAgICAgICogQ29waWVzIHByb3BlcnRpZXMgaW50byB0aGlzIG9iamVjdC5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IHByb3BlcnRpZXMgVGhlIHByb3BlcnRpZXMgdG8gbWl4IGluLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgTXlUeXBlLm1peEluKHtcblx0ICAgICAgICAgICAgICogICAgICAgICBmaWVsZDogJ3ZhbHVlJ1xuXHQgICAgICAgICAgICAgKiAgICAgfSk7XG5cdCAgICAgICAgICAgICAqL1xuXHQgICAgICAgICAgICBtaXhJbjogZnVuY3Rpb24gKHByb3BlcnRpZXMpIHtcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIHByb3BlcnR5TmFtZSBpbiBwcm9wZXJ0aWVzKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgaWYgKHByb3BlcnRpZXMuaGFzT3duUHJvcGVydHkocHJvcGVydHlOYW1lKSkge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB0aGlzW3Byb3BlcnR5TmFtZV0gPSBwcm9wZXJ0aWVzW3Byb3BlcnR5TmFtZV07XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAvLyBJRSB3b24ndCBjb3B5IHRvU3RyaW5nIHVzaW5nIHRoZSBsb29wIGFib3ZlXG5cdCAgICAgICAgICAgICAgICBpZiAocHJvcGVydGllcy5oYXNPd25Qcm9wZXJ0eSgndG9TdHJpbmcnKSkge1xuXHQgICAgICAgICAgICAgICAgICAgIHRoaXMudG9TdHJpbmcgPSBwcm9wZXJ0aWVzLnRvU3RyaW5nO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9LFxuXG5cdCAgICAgICAgICAgIC8qKlxuXHQgICAgICAgICAgICAgKiBDcmVhdGVzIGEgY29weSBvZiB0aGlzIG9iamVjdC5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQHJldHVybiB7T2JqZWN0fSBUaGUgY2xvbmUuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqICAgICB2YXIgY2xvbmUgPSBpbnN0YW5jZS5jbG9uZSgpO1xuXHQgICAgICAgICAgICAgKi9cblx0ICAgICAgICAgICAgY2xvbmU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiB0aGlzLmluaXQucHJvdG90eXBlLmV4dGVuZCh0aGlzKTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH07XG5cdCAgICB9KCkpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFuIGFycmF5IG9mIDMyLWJpdCB3b3Jkcy5cblx0ICAgICAqXG5cdCAgICAgKiBAcHJvcGVydHkge0FycmF5fSB3b3JkcyBUaGUgYXJyYXkgb2YgMzItYml0IHdvcmRzLlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IHNpZ0J5dGVzIFRoZSBudW1iZXIgb2Ygc2lnbmlmaWNhbnQgYnl0ZXMgaW4gdGhpcyB3b3JkIGFycmF5LlxuXHQgICAgICovXG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5ID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtBcnJheX0gd29yZHMgKE9wdGlvbmFsKSBBbiBhcnJheSBvZiAzMi1iaXQgd29yZHMuXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IHNpZ0J5dGVzIChPcHRpb25hbCkgVGhlIG51bWJlciBvZiBzaWduaWZpY2FudCBieXRlcyBpbiB0aGUgd29yZHMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5saWIuV29yZEFycmF5LmNyZWF0ZSgpO1xuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMubGliLldvcmRBcnJheS5jcmVhdGUoWzB4MDAwMTAyMDMsIDB4MDQwNTA2MDddKTtcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLmxpYi5Xb3JkQXJyYXkuY3JlYXRlKFsweDAwMDEwMjAzLCAweDA0MDUwNjA3XSwgNik7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKHdvcmRzLCBzaWdCeXRlcykge1xuXHQgICAgICAgICAgICB3b3JkcyA9IHRoaXMud29yZHMgPSB3b3JkcyB8fCBbXTtcblxuXHQgICAgICAgICAgICBpZiAoc2lnQnl0ZXMgIT0gdW5kZWZpbmVkKSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLnNpZ0J5dGVzID0gc2lnQnl0ZXM7XG5cdCAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLnNpZ0J5dGVzID0gd29yZHMubGVuZ3RoICogNDtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyB0aGlzIHdvcmQgYXJyYXkgdG8gYSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0VuY29kZXJ9IGVuY29kZXIgKE9wdGlvbmFsKSBUaGUgZW5jb2Rpbmcgc3RyYXRlZ3kgdG8gdXNlLiBEZWZhdWx0OiBDcnlwdG9KUy5lbmMuSGV4XG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBzdHJpbmdpZmllZCB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgc3RyaW5nID0gd29yZEFycmF5ICsgJyc7XG5cdCAgICAgICAgICogICAgIHZhciBzdHJpbmcgPSB3b3JkQXJyYXkudG9TdHJpbmcoKTtcblx0ICAgICAgICAgKiAgICAgdmFyIHN0cmluZyA9IHdvcmRBcnJheS50b1N0cmluZyhDcnlwdG9KUy5lbmMuVXRmOCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgdG9TdHJpbmc6IGZ1bmN0aW9uIChlbmNvZGVyKSB7XG5cdCAgICAgICAgICAgIHJldHVybiAoZW5jb2RlciB8fCBIZXgpLnN0cmluZ2lmeSh0aGlzKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uY2F0ZW5hdGVzIGEgd29yZCBhcnJheSB0byB0aGlzIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gd29yZEFycmF5IFRoZSB3b3JkIGFycmF5IHRvIGFwcGVuZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhpcyB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB3b3JkQXJyYXkxLmNvbmNhdCh3b3JkQXJyYXkyKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjb25jYXQ6IGZ1bmN0aW9uICh3b3JkQXJyYXkpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciB0aGlzV29yZHMgPSB0aGlzLndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgdGhhdFdvcmRzID0gd29yZEFycmF5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgdGhpc1NpZ0J5dGVzID0gdGhpcy5zaWdCeXRlcztcblx0ICAgICAgICAgICAgdmFyIHRoYXRTaWdCeXRlcyA9IHdvcmRBcnJheS5zaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDbGFtcCBleGNlc3MgYml0c1xuXHQgICAgICAgICAgICB0aGlzLmNsYW1wKCk7XG5cblx0ICAgICAgICAgICAgLy8gQ29uY2F0XG5cdCAgICAgICAgICAgIGlmICh0aGlzU2lnQnl0ZXMgJSA0KSB7XG5cdCAgICAgICAgICAgICAgICAvLyBDb3B5IG9uZSBieXRlIGF0IGEgdGltZVxuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0aGF0U2lnQnl0ZXM7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciB0aGF0Qnl0ZSA9ICh0aGF0V29yZHNbaSA+Pj4gMl0gPj4+ICgyNCAtIChpICUgNCkgKiA4KSkgJiAweGZmO1xuXHQgICAgICAgICAgICAgICAgICAgIHRoaXNXb3Jkc1sodGhpc1NpZ0J5dGVzICsgaSkgPj4+IDJdIHw9IHRoYXRCeXRlIDw8ICgyNCAtICgodGhpc1NpZ0J5dGVzICsgaSkgJSA0KSAqIDgpO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgLy8gQ29weSBvbmUgd29yZCBhdCBhIHRpbWVcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhhdFNpZ0J5dGVzOyBpICs9IDQpIHtcblx0ICAgICAgICAgICAgICAgICAgICB0aGlzV29yZHNbKHRoaXNTaWdCeXRlcyArIGkpID4+PiAyXSA9IHRoYXRXb3Jkc1tpID4+PiAyXTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB0aGlzLnNpZ0J5dGVzICs9IHRoYXRTaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDaGFpbmFibGVcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXM7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFJlbW92ZXMgaW5zaWduaWZpY2FudCBiaXRzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB3b3JkQXJyYXkuY2xhbXAoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjbGFtcDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gdGhpcy53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHNpZ0J5dGVzID0gdGhpcy5zaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDbGFtcFxuXHQgICAgICAgICAgICB3b3Jkc1tzaWdCeXRlcyA+Pj4gMl0gJj0gMHhmZmZmZmZmZiA8PCAoMzIgLSAoc2lnQnl0ZXMgJSA0KSAqIDgpO1xuXHQgICAgICAgICAgICB3b3Jkcy5sZW5ndGggPSBNYXRoLmNlaWwoc2lnQnl0ZXMgLyA0KTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyBhIGNvcHkgb2YgdGhpcyB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgY2xvbmUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjbG9uZSA9IHdvcmRBcnJheS5jbG9uZSgpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNsb25lOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHZhciBjbG9uZSA9IEJhc2UuY2xvbmUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgY2xvbmUud29yZHMgPSB0aGlzLndvcmRzLnNsaWNlKDApO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBjbG9uZTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyBhIHdvcmQgYXJyYXkgZmlsbGVkIHdpdGggcmFuZG9tIGJ5dGVzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IG5CeXRlcyBUaGUgbnVtYmVyIG9mIHJhbmRvbSBieXRlcyB0byBnZW5lcmF0ZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHJhbmRvbSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMubGliLldvcmRBcnJheS5yYW5kb20oMTYpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHJhbmRvbTogZnVuY3Rpb24gKG5CeXRlcykge1xuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSBbXTtcblxuXHQgICAgICAgICAgICB2YXIgciA9IChmdW5jdGlvbiAobV93KSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgbV93ID0gbV93O1xuXHQgICAgICAgICAgICAgICAgdmFyIG1feiA9IDB4M2FkZTY4YjE7XG5cdCAgICAgICAgICAgICAgICB2YXIgbWFzayA9IDB4ZmZmZmZmZmY7XG5cblx0ICAgICAgICAgICAgICAgIHJldHVybiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgbV96ID0gKDB4OTA2OSAqIChtX3ogJiAweEZGRkYpICsgKG1feiA+PiAweDEwKSkgJiBtYXNrO1xuXHQgICAgICAgICAgICAgICAgICAgIG1fdyA9ICgweDQ2NTAgKiAobV93ICYgMHhGRkZGKSArIChtX3cgPj4gMHgxMCkpICYgbWFzaztcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgcmVzdWx0ID0gKChtX3ogPDwgMHgxMCkgKyBtX3cpICYgbWFzaztcblx0ICAgICAgICAgICAgICAgICAgICByZXN1bHQgLz0gMHgxMDAwMDAwMDA7XG5cdCAgICAgICAgICAgICAgICAgICAgcmVzdWx0ICs9IDAuNTtcblx0ICAgICAgICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0ICogKE1hdGgucmFuZG9tKCkgPiAuNSA/IDEgOiAtMSk7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH0pO1xuXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwLCByY2FjaGU7IGkgPCBuQnl0ZXM7IGkgKz0gNCkge1xuXHQgICAgICAgICAgICAgICAgdmFyIF9yID0gcigocmNhY2hlIHx8IE1hdGgucmFuZG9tKCkpICogMHgxMDAwMDAwMDApO1xuXG5cdCAgICAgICAgICAgICAgICByY2FjaGUgPSBfcigpICogMHgzYWRlNjdiNztcblx0ICAgICAgICAgICAgICAgIHdvcmRzLnB1c2goKF9yKCkgKiAweDEwMDAwMDAwMCkgfCAwKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBuZXcgV29yZEFycmF5LmluaXQod29yZHMsIG5CeXRlcyk7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogRW5jb2RlciBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX2VuYyA9IEMuZW5jID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogSGV4IGVuY29kaW5nIHN0cmF0ZWd5LlxuXHQgICAgICovXG5cdCAgICB2YXIgSGV4ID0gQ19lbmMuSGV4ID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgd29yZCBhcnJheSB0byBhIGhleCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gd29yZEFycmF5IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7c3RyaW5nfSBUaGUgaGV4IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGhleFN0cmluZyA9IENyeXB0b0pTLmVuYy5IZXguc3RyaW5naWZ5KHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgc3RyaW5naWZ5OiBmdW5jdGlvbiAod29yZEFycmF5KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSB3b3JkQXJyYXkud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBzaWdCeXRlcyA9IHdvcmRBcnJheS5zaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0XG5cdCAgICAgICAgICAgIHZhciBoZXhDaGFycyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHNpZ0J5dGVzOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHZhciBiaXRlID0gKHdvcmRzW2kgPj4+IDJdID4+PiAoMjQgLSAoaSAlIDQpICogOCkpICYgMHhmZjtcblx0ICAgICAgICAgICAgICAgIGhleENoYXJzLnB1c2goKGJpdGUgPj4+IDQpLnRvU3RyaW5nKDE2KSk7XG5cdCAgICAgICAgICAgICAgICBoZXhDaGFycy5wdXNoKChiaXRlICYgMHgwZikudG9TdHJpbmcoMTYpKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBoZXhDaGFycy5qb2luKCcnKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBoZXggc3RyaW5nIHRvIGEgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSBoZXhTdHIgVGhlIGhleCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMuZW5jLkhleC5wYXJzZShoZXhTdHJpbmcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHBhcnNlOiBmdW5jdGlvbiAoaGV4U3RyKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBoZXhTdHJMZW5ndGggPSBoZXhTdHIubGVuZ3RoO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaGV4U3RyTGVuZ3RoOyBpICs9IDIpIHtcblx0ICAgICAgICAgICAgICAgIHdvcmRzW2kgPj4+IDNdIHw9IHBhcnNlSW50KGhleFN0ci5zdWJzdHIoaSwgMiksIDE2KSA8PCAoMjQgLSAoaSAlIDgpICogNCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gbmV3IFdvcmRBcnJheS5pbml0KHdvcmRzLCBoZXhTdHJMZW5ndGggLyAyKTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIExhdGluMSBlbmNvZGluZyBzdHJhdGVneS5cblx0ICAgICAqL1xuXHQgICAgdmFyIExhdGluMSA9IENfZW5jLkxhdGluMSA9IHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBhIHdvcmQgYXJyYXkgdG8gYSBMYXRpbjEgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBUaGUgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge3N0cmluZ30gVGhlIExhdGluMSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBsYXRpbjFTdHJpbmcgPSBDcnlwdG9KUy5lbmMuTGF0aW4xLnN0cmluZ2lmeSh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHN0cmluZ2lmeTogZnVuY3Rpb24gKHdvcmRBcnJheSkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gd29yZEFycmF5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgc2lnQnl0ZXMgPSB3b3JkQXJyYXkuc2lnQnl0ZXM7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydFxuXHQgICAgICAgICAgICB2YXIgbGF0aW4xQ2hhcnMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzaWdCeXRlczsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgYml0ZSA9ICh3b3Jkc1tpID4+PiAyXSA+Pj4gKDI0IC0gKGkgJSA0KSAqIDgpKSAmIDB4ZmY7XG5cdCAgICAgICAgICAgICAgICBsYXRpbjFDaGFycy5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUoYml0ZSkpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGxhdGluMUNoYXJzLmpvaW4oJycpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBhIExhdGluMSBzdHJpbmcgdG8gYSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtzdHJpbmd9IGxhdGluMVN0ciBUaGUgTGF0aW4xIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5lbmMuTGF0aW4xLnBhcnNlKGxhdGluMVN0cmluZyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcGFyc2U6IGZ1bmN0aW9uIChsYXRpbjFTdHIpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGxhdGluMVN0ckxlbmd0aCA9IGxhdGluMVN0ci5sZW5ndGg7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydFxuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBsYXRpbjFTdHJMZW5ndGg7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbaSA+Pj4gMl0gfD0gKGxhdGluMVN0ci5jaGFyQ29kZUF0KGkpICYgMHhmZikgPDwgKDI0IC0gKGkgJSA0KSAqIDgpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIG5ldyBXb3JkQXJyYXkuaW5pdCh3b3JkcywgbGF0aW4xU3RyTGVuZ3RoKTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIFVURi04IGVuY29kaW5nIHN0cmF0ZWd5LlxuXHQgICAgICovXG5cdCAgICB2YXIgVXRmOCA9IENfZW5jLlV0ZjggPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSB3b3JkIGFycmF5IHRvIGEgVVRGLTggc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBUaGUgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge3N0cmluZ30gVGhlIFVURi04IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHV0ZjhTdHJpbmcgPSBDcnlwdG9KUy5lbmMuVXRmOC5zdHJpbmdpZnkod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBzdHJpbmdpZnk6IGZ1bmN0aW9uICh3b3JkQXJyYXkpIHtcblx0ICAgICAgICAgICAgdHJ5IHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiBkZWNvZGVVUklDb21wb25lbnQoZXNjYXBlKExhdGluMS5zdHJpbmdpZnkod29yZEFycmF5KSkpO1xuXHQgICAgICAgICAgICB9IGNhdGNoIChlKSB7XG5cdCAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ01hbGZvcm1lZCBVVEYtOCBkYXRhJyk7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBVVEYtOCBzdHJpbmcgdG8gYSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtzdHJpbmd9IHV0ZjhTdHIgVGhlIFVURi04IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5lbmMuVXRmOC5wYXJzZSh1dGY4U3RyaW5nKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBwYXJzZTogZnVuY3Rpb24gKHV0ZjhTdHIpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIExhdGluMS5wYXJzZSh1bmVzY2FwZShlbmNvZGVVUklDb21wb25lbnQodXRmOFN0cikpKTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFic3RyYWN0IGJ1ZmZlcmVkIGJsb2NrIGFsZ29yaXRobSB0ZW1wbGF0ZS5cblx0ICAgICAqXG5cdCAgICAgKiBUaGUgcHJvcGVydHkgYmxvY2tTaXplIG11c3QgYmUgaW1wbGVtZW50ZWQgaW4gYSBjb25jcmV0ZSBzdWJ0eXBlLlxuXHQgICAgICpcblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBfbWluQnVmZmVyU2l6ZSBUaGUgbnVtYmVyIG9mIGJsb2NrcyB0aGF0IHNob3VsZCBiZSBrZXB0IHVucHJvY2Vzc2VkIGluIHRoZSBidWZmZXIuIERlZmF1bHQ6IDBcblx0ICAgICAqL1xuXHQgICAgdmFyIEJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0gPSBDX2xpYi5CdWZmZXJlZEJsb2NrQWxnb3JpdGhtID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFJlc2V0cyB0aGlzIGJsb2NrIGFsZ29yaXRobSdzIGRhdGEgYnVmZmVyIHRvIGl0cyBpbml0aWFsIHN0YXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBidWZmZXJlZEJsb2NrQWxnb3JpdGhtLnJlc2V0KCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gSW5pdGlhbCB2YWx1ZXNcblx0ICAgICAgICAgICAgdGhpcy5fZGF0YSA9IG5ldyBXb3JkQXJyYXkuaW5pdCgpO1xuXHQgICAgICAgICAgICB0aGlzLl9uRGF0YUJ5dGVzID0gMDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQWRkcyBuZXcgZGF0YSB0byB0aGlzIGJsb2NrIGFsZ29yaXRobSdzIGJ1ZmZlci5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gZGF0YSBUaGUgZGF0YSB0byBhcHBlbmQuIFN0cmluZ3MgYXJlIGNvbnZlcnRlZCB0byBhIFdvcmRBcnJheSB1c2luZyBVVEYtOC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgYnVmZmVyZWRCbG9ja0FsZ29yaXRobS5fYXBwZW5kKCdkYXRhJyk7XG5cdCAgICAgICAgICogICAgIGJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0uX2FwcGVuZCh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIF9hcHBlbmQ6IGZ1bmN0aW9uIChkYXRhKSB7XG5cdCAgICAgICAgICAgIC8vIENvbnZlcnQgc3RyaW5nIHRvIFdvcmRBcnJheSwgZWxzZSBhc3N1bWUgV29yZEFycmF5IGFscmVhZHlcblx0ICAgICAgICAgICAgaWYgKHR5cGVvZiBkYXRhID09ICdzdHJpbmcnKSB7XG5cdCAgICAgICAgICAgICAgICBkYXRhID0gVXRmOC5wYXJzZShkYXRhKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEFwcGVuZFxuXHQgICAgICAgICAgICB0aGlzLl9kYXRhLmNvbmNhdChkYXRhKTtcblx0ICAgICAgICAgICAgdGhpcy5fbkRhdGFCeXRlcyArPSBkYXRhLnNpZ0J5dGVzO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBQcm9jZXNzZXMgYXZhaWxhYmxlIGRhdGEgYmxvY2tzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogVGhpcyBtZXRob2QgaW52b2tlcyBfZG9Qcm9jZXNzQmxvY2sob2Zmc2V0KSwgd2hpY2ggbXVzdCBiZSBpbXBsZW1lbnRlZCBieSBhIGNvbmNyZXRlIHN1YnR5cGUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge2Jvb2xlYW59IGRvRmx1c2ggV2hldGhlciBhbGwgYmxvY2tzIGFuZCBwYXJ0aWFsIGJsb2NrcyBzaG91bGQgYmUgcHJvY2Vzc2VkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgcHJvY2Vzc2VkIGRhdGEuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBwcm9jZXNzZWREYXRhID0gYnVmZmVyZWRCbG9ja0FsZ29yaXRobS5fcHJvY2VzcygpO1xuXHQgICAgICAgICAqICAgICB2YXIgcHJvY2Vzc2VkRGF0YSA9IGJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0uX3Byb2Nlc3MoISEnZmx1c2gnKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBfcHJvY2VzczogZnVuY3Rpb24gKGRvRmx1c2gpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkYXRhID0gdGhpcy5fZGF0YTtcblx0ICAgICAgICAgICAgdmFyIGRhdGFXb3JkcyA9IGRhdGEud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBkYXRhU2lnQnl0ZXMgPSBkYXRhLnNpZ0J5dGVzO1xuXHQgICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gdGhpcy5ibG9ja1NpemU7XG5cdCAgICAgICAgICAgIHZhciBibG9ja1NpemVCeXRlcyA9IGJsb2NrU2l6ZSAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gQ291bnQgYmxvY2tzIHJlYWR5XG5cdCAgICAgICAgICAgIHZhciBuQmxvY2tzUmVhZHkgPSBkYXRhU2lnQnl0ZXMgLyBibG9ja1NpemVCeXRlcztcblx0ICAgICAgICAgICAgaWYgKGRvRmx1c2gpIHtcblx0ICAgICAgICAgICAgICAgIC8vIFJvdW5kIHVwIHRvIGluY2x1ZGUgcGFydGlhbCBibG9ja3Ncblx0ICAgICAgICAgICAgICAgIG5CbG9ja3NSZWFkeSA9IE1hdGguY2VpbChuQmxvY2tzUmVhZHkpO1xuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgLy8gUm91bmQgZG93biB0byBpbmNsdWRlIG9ubHkgZnVsbCBibG9ja3MsXG5cdCAgICAgICAgICAgICAgICAvLyBsZXNzIHRoZSBudW1iZXIgb2YgYmxvY2tzIHRoYXQgbXVzdCByZW1haW4gaW4gdGhlIGJ1ZmZlclxuXHQgICAgICAgICAgICAgICAgbkJsb2Nrc1JlYWR5ID0gTWF0aC5tYXgoKG5CbG9ja3NSZWFkeSB8IDApIC0gdGhpcy5fbWluQnVmZmVyU2l6ZSwgMCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBDb3VudCB3b3JkcyByZWFkeVxuXHQgICAgICAgICAgICB2YXIgbldvcmRzUmVhZHkgPSBuQmxvY2tzUmVhZHkgKiBibG9ja1NpemU7XG5cblx0ICAgICAgICAgICAgLy8gQ291bnQgYnl0ZXMgcmVhZHlcblx0ICAgICAgICAgICAgdmFyIG5CeXRlc1JlYWR5ID0gTWF0aC5taW4obldvcmRzUmVhZHkgKiA0LCBkYXRhU2lnQnl0ZXMpO1xuXG5cdCAgICAgICAgICAgIC8vIFByb2Nlc3MgYmxvY2tzXG5cdCAgICAgICAgICAgIGlmIChuV29yZHNSZWFkeSkge1xuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgb2Zmc2V0ID0gMDsgb2Zmc2V0IDwgbldvcmRzUmVhZHk7IG9mZnNldCArPSBibG9ja1NpemUpIHtcblx0ICAgICAgICAgICAgICAgICAgICAvLyBQZXJmb3JtIGNvbmNyZXRlLWFsZ29yaXRobSBsb2dpY1xuXHQgICAgICAgICAgICAgICAgICAgIHRoaXMuX2RvUHJvY2Vzc0Jsb2NrKGRhdGFXb3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIHByb2Nlc3NlZCB3b3Jkc1xuXHQgICAgICAgICAgICAgICAgdmFyIHByb2Nlc3NlZFdvcmRzID0gZGF0YVdvcmRzLnNwbGljZSgwLCBuV29yZHNSZWFkeSk7XG5cdCAgICAgICAgICAgICAgICBkYXRhLnNpZ0J5dGVzIC09IG5CeXRlc1JlYWR5O1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gUmV0dXJuIHByb2Nlc3NlZCB3b3Jkc1xuXHQgICAgICAgICAgICByZXR1cm4gbmV3IFdvcmRBcnJheS5pbml0KHByb2Nlc3NlZFdvcmRzLCBuQnl0ZXNSZWFkeSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgYSBjb3B5IG9mIHRoaXMgb2JqZWN0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7T2JqZWN0fSBUaGUgY2xvbmUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjbG9uZSA9IGJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0uY2xvbmUoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBCYXNlLmNsb25lLmNhbGwodGhpcyk7XG5cdCAgICAgICAgICAgIGNsb25lLl9kYXRhID0gdGhpcy5fZGF0YS5jbG9uZSgpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBjbG9uZTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX21pbkJ1ZmZlclNpemU6IDBcblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFic3RyYWN0IGhhc2hlciB0ZW1wbGF0ZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcHJvcGVydHkge251bWJlcn0gYmxvY2tTaXplIFRoZSBudW1iZXIgb2YgMzItYml0IHdvcmRzIHRoaXMgaGFzaGVyIG9wZXJhdGVzIG9uLiBEZWZhdWx0OiAxNiAoNTEyIGJpdHMpXG5cdCAgICAgKi9cblx0ICAgIHZhciBIYXNoZXIgPSBDX2xpYi5IYXNoZXIgPSBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNmZzogQmFzZS5leHRlbmQoKSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCBoYXNoZXIuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoaXMgaGFzaCBjb21wdXRhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGhhc2hlciA9IENyeXB0b0pTLmFsZ28uU0hBMjU2LmNyZWF0ZSgpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGluaXQ6IGZ1bmN0aW9uIChjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIHRoaXMuY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cblx0ICAgICAgICAgICAgLy8gU2V0IGluaXRpYWwgdmFsdWVzXG5cdCAgICAgICAgICAgIHRoaXMucmVzZXQoKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogUmVzZXRzIHRoaXMgaGFzaGVyIHRvIGl0cyBpbml0aWFsIHN0YXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBoYXNoZXIucmVzZXQoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICByZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBSZXNldCBkYXRhIGJ1ZmZlclxuXHQgICAgICAgICAgICBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtLnJlc2V0LmNhbGwodGhpcyk7XG5cblx0ICAgICAgICAgICAgLy8gUGVyZm9ybSBjb25jcmV0ZS1oYXNoZXIgbG9naWNcblx0ICAgICAgICAgICAgdGhpcy5fZG9SZXNldCgpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBVcGRhdGVzIHRoaXMgaGFzaGVyIHdpdGggYSBtZXNzYWdlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlVXBkYXRlIFRoZSBtZXNzYWdlIHRvIGFwcGVuZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0hhc2hlcn0gVGhpcyBoYXNoZXIuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIGhhc2hlci51cGRhdGUoJ21lc3NhZ2UnKTtcblx0ICAgICAgICAgKiAgICAgaGFzaGVyLnVwZGF0ZSh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHVwZGF0ZTogZnVuY3Rpb24gKG1lc3NhZ2VVcGRhdGUpIHtcblx0ICAgICAgICAgICAgLy8gQXBwZW5kXG5cdCAgICAgICAgICAgIHRoaXMuX2FwcGVuZChtZXNzYWdlVXBkYXRlKTtcblxuXHQgICAgICAgICAgICAvLyBVcGRhdGUgdGhlIGhhc2hcblx0ICAgICAgICAgICAgdGhpcy5fcHJvY2VzcygpO1xuXG5cdCAgICAgICAgICAgIC8vIENoYWluYWJsZVxuXHQgICAgICAgICAgICByZXR1cm4gdGhpcztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogRmluYWxpemVzIHRoZSBoYXNoIGNvbXB1dGF0aW9uLlxuXHQgICAgICAgICAqIE5vdGUgdGhhdCB0aGUgZmluYWxpemUgb3BlcmF0aW9uIGlzIGVmZmVjdGl2ZWx5IGEgZGVzdHJ1Y3RpdmUsIHJlYWQtb25jZSBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2VVcGRhdGUgKE9wdGlvbmFsKSBBIGZpbmFsIG1lc3NhZ2UgdXBkYXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgaGFzaC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGhhc2ggPSBoYXNoZXIuZmluYWxpemUoKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGhhc2ggPSBoYXNoZXIuZmluYWxpemUoJ21lc3NhZ2UnKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGhhc2ggPSBoYXNoZXIuZmluYWxpemUod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBmaW5hbGl6ZTogZnVuY3Rpb24gKG1lc3NhZ2VVcGRhdGUpIHtcblx0ICAgICAgICAgICAgLy8gRmluYWwgbWVzc2FnZSB1cGRhdGVcblx0ICAgICAgICAgICAgaWYgKG1lc3NhZ2VVcGRhdGUpIHtcblx0ICAgICAgICAgICAgICAgIHRoaXMuX2FwcGVuZChtZXNzYWdlVXBkYXRlKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFBlcmZvcm0gY29uY3JldGUtaGFzaGVyIGxvZ2ljXG5cdCAgICAgICAgICAgIHZhciBoYXNoID0gdGhpcy5fZG9GaW5hbGl6ZSgpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBoYXNoO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBibG9ja1NpemU6IDUxMi8zMixcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgYSBzaG9ydGN1dCBmdW5jdGlvbiB0byBhIGhhc2hlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0hhc2hlcn0gaGFzaGVyIFRoZSBoYXNoZXIgdG8gY3JlYXRlIGEgaGVscGVyIGZvci5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0Z1bmN0aW9ufSBUaGUgc2hvcnRjdXQgZnVuY3Rpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBTSEEyNTYgPSBDcnlwdG9KUy5saWIuSGFzaGVyLl9jcmVhdGVIZWxwZXIoQ3J5cHRvSlMuYWxnby5TSEEyNTYpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIF9jcmVhdGVIZWxwZXI6IGZ1bmN0aW9uIChoYXNoZXIpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChtZXNzYWdlLCBjZmcpIHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiBuZXcgaGFzaGVyLmluaXQoY2ZnKS5maW5hbGl6ZShtZXNzYWdlKTtcblx0ICAgICAgICAgICAgfTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyBhIHNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBITUFDJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7SGFzaGVyfSBoYXNoZXIgVGhlIGhhc2hlciB0byB1c2UgaW4gdGhpcyBITUFDIGhlbHBlci5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0Z1bmN0aW9ufSBUaGUgc2hvcnRjdXQgZnVuY3Rpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBIbWFjU0hBMjU2ID0gQ3J5cHRvSlMubGliLkhhc2hlci5fY3JlYXRlSG1hY0hlbHBlcihDcnlwdG9KUy5hbGdvLlNIQTI1Nik7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgX2NyZWF0ZUhtYWNIZWxwZXI6IGZ1bmN0aW9uIChoYXNoZXIpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChtZXNzYWdlLCBrZXkpIHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiBuZXcgQ19hbGdvLkhNQUMuaW5pdChoYXNoZXIsIGtleSkuZmluYWxpemUobWVzc2FnZSk7XG5cdCAgICAgICAgICAgIH07XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogQWxnb3JpdGhtIG5hbWVzcGFjZS5cblx0ICAgICAqL1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbyA9IHt9O1xuXG5cdCAgICByZXR1cm4gQztcblx0fShNYXRoKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlM7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5KSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgQ19lbmMgPSBDLmVuYztcblxuXHQgICAgLyoqXG5cdCAgICAgKiBCYXNlNjQgZW5jb2Rpbmcgc3RyYXRlZ3kuXG5cdCAgICAgKi9cblx0ICAgIHZhciBCYXNlNjQgPSBDX2VuYy5CYXNlNjQgPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSB3b3JkIGFycmF5IHRvIGEgQmFzZTY0IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSB3b3JkQXJyYXkgVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBCYXNlNjQgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgYmFzZTY0U3RyaW5nID0gQ3J5cHRvSlMuZW5jLkJhc2U2NC5zdHJpbmdpZnkod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBzdHJpbmdpZnk6IGZ1bmN0aW9uICh3b3JkQXJyYXkpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IHdvcmRBcnJheS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHNpZ0J5dGVzID0gd29yZEFycmF5LnNpZ0J5dGVzO1xuXHQgICAgICAgICAgICB2YXIgbWFwID0gdGhpcy5fbWFwO1xuXG5cdCAgICAgICAgICAgIC8vIENsYW1wIGV4Y2VzcyBiaXRzXG5cdCAgICAgICAgICAgIHdvcmRBcnJheS5jbGFtcCgpO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIGJhc2U2NENoYXJzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2lnQnl0ZXM7IGkgKz0gMykge1xuXHQgICAgICAgICAgICAgICAgdmFyIGJ5dGUxID0gKHdvcmRzW2kgPj4+IDJdICAgICAgID4+PiAoMjQgLSAoaSAlIDQpICogOCkpICAgICAgICYgMHhmZjtcblx0ICAgICAgICAgICAgICAgIHZhciBieXRlMiA9ICh3b3Jkc1soaSArIDEpID4+PiAyXSA+Pj4gKDI0IC0gKChpICsgMSkgJSA0KSAqIDgpKSAmIDB4ZmY7XG5cdCAgICAgICAgICAgICAgICB2YXIgYnl0ZTMgPSAod29yZHNbKGkgKyAyKSA+Pj4gMl0gPj4+ICgyNCAtICgoaSArIDIpICUgNCkgKiA4KSkgJiAweGZmO1xuXG5cdCAgICAgICAgICAgICAgICB2YXIgdHJpcGxldCA9IChieXRlMSA8PCAxNikgfCAoYnl0ZTIgPDwgOCkgfCBieXRlMztcblxuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaiA9IDA7IChqIDwgNCkgJiYgKGkgKyBqICogMC43NSA8IHNpZ0J5dGVzKTsgaisrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgYmFzZTY0Q2hhcnMucHVzaChtYXAuY2hhckF0KCh0cmlwbGV0ID4+PiAoNiAqICgzIC0gaikpKSAmIDB4M2YpKTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEFkZCBwYWRkaW5nXG5cdCAgICAgICAgICAgIHZhciBwYWRkaW5nQ2hhciA9IG1hcC5jaGFyQXQoNjQpO1xuXHQgICAgICAgICAgICBpZiAocGFkZGluZ0NoYXIpIHtcblx0ICAgICAgICAgICAgICAgIHdoaWxlIChiYXNlNjRDaGFycy5sZW5ndGggJSA0KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgYmFzZTY0Q2hhcnMucHVzaChwYWRkaW5nQ2hhcik7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gYmFzZTY0Q2hhcnMuam9pbignJyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgQmFzZTY0IHN0cmluZyB0byBhIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gYmFzZTY0U3RyIFRoZSBCYXNlNjQgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLmVuYy5CYXNlNjQucGFyc2UoYmFzZTY0U3RyaW5nKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBwYXJzZTogZnVuY3Rpb24gKGJhc2U2NFN0cikge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGJhc2U2NFN0ckxlbmd0aCA9IGJhc2U2NFN0ci5sZW5ndGg7XG5cdCAgICAgICAgICAgIHZhciBtYXAgPSB0aGlzLl9tYXA7XG5cdCAgICAgICAgICAgIHZhciByZXZlcnNlTWFwID0gdGhpcy5fcmV2ZXJzZU1hcDtcblxuXHQgICAgICAgICAgICBpZiAoIXJldmVyc2VNYXApIHtcblx0ICAgICAgICAgICAgICAgICAgICByZXZlcnNlTWFwID0gdGhpcy5fcmV2ZXJzZU1hcCA9IFtdO1xuXHQgICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgbWFwLmxlbmd0aDsgaisrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHJldmVyc2VNYXBbbWFwLmNoYXJDb2RlQXQoaildID0gajtcblx0ICAgICAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBJZ25vcmUgcGFkZGluZ1xuXHQgICAgICAgICAgICB2YXIgcGFkZGluZ0NoYXIgPSBtYXAuY2hhckF0KDY0KTtcblx0ICAgICAgICAgICAgaWYgKHBhZGRpbmdDaGFyKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgcGFkZGluZ0luZGV4ID0gYmFzZTY0U3RyLmluZGV4T2YocGFkZGluZ0NoYXIpO1xuXHQgICAgICAgICAgICAgICAgaWYgKHBhZGRpbmdJbmRleCAhPT0gLTEpIHtcblx0ICAgICAgICAgICAgICAgICAgICBiYXNlNjRTdHJMZW5ndGggPSBwYWRkaW5nSW5kZXg7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0XG5cdCAgICAgICAgICAgIHJldHVybiBwYXJzZUxvb3AoYmFzZTY0U3RyLCBiYXNlNjRTdHJMZW5ndGgsIHJldmVyc2VNYXApO1xuXG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9tYXA6ICdBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OSsvPSdcblx0ICAgIH07XG5cblx0ICAgIGZ1bmN0aW9uIHBhcnNlTG9vcChiYXNlNjRTdHIsIGJhc2U2NFN0ckxlbmd0aCwgcmV2ZXJzZU1hcCkge1xuXHQgICAgICB2YXIgd29yZHMgPSBbXTtcblx0ICAgICAgdmFyIG5CeXRlcyA9IDA7XG5cdCAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYmFzZTY0U3RyTGVuZ3RoOyBpKyspIHtcblx0ICAgICAgICAgIGlmIChpICUgNCkge1xuXHQgICAgICAgICAgICAgIHZhciBiaXRzMSA9IHJldmVyc2VNYXBbYmFzZTY0U3RyLmNoYXJDb2RlQXQoaSAtIDEpXSA8PCAoKGkgJSA0KSAqIDIpO1xuXHQgICAgICAgICAgICAgIHZhciBiaXRzMiA9IHJldmVyc2VNYXBbYmFzZTY0U3RyLmNoYXJDb2RlQXQoaSldID4+PiAoNiAtIChpICUgNCkgKiAyKTtcblx0ICAgICAgICAgICAgICB3b3Jkc1tuQnl0ZXMgPj4+IDJdIHw9IChiaXRzMSB8IGJpdHMyKSA8PCAoMjQgLSAobkJ5dGVzICUgNCkgKiA4KTtcblx0ICAgICAgICAgICAgICBuQnl0ZXMrKztcblx0ICAgICAgICAgIH1cblx0ICAgICAgfVxuXHQgICAgICByZXR1cm4gV29yZEFycmF5LmNyZWF0ZSh3b3JkcywgbkJ5dGVzKTtcblx0ICAgIH1cblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5lbmMuQmFzZTY0O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5O1xuXHQgICAgdmFyIENfZW5jID0gQy5lbmM7XG5cblx0ICAgIC8qKlxuXHQgICAgICogVVRGLTE2IEJFIGVuY29kaW5nIHN0cmF0ZWd5LlxuXHQgICAgICovXG5cdCAgICB2YXIgVXRmMTZCRSA9IENfZW5jLlV0ZjE2ID0gQ19lbmMuVXRmMTZCRSA9IHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBhIHdvcmQgYXJyYXkgdG8gYSBVVEYtMTYgQkUgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBUaGUgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge3N0cmluZ30gVGhlIFVURi0xNiBCRSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB1dGYxNlN0cmluZyA9IENyeXB0b0pTLmVuYy5VdGYxNi5zdHJpbmdpZnkod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBzdHJpbmdpZnk6IGZ1bmN0aW9uICh3b3JkQXJyYXkpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IHdvcmRBcnJheS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHNpZ0J5dGVzID0gd29yZEFycmF5LnNpZ0J5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIHV0ZjE2Q2hhcnMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzaWdCeXRlczsgaSArPSAyKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgY29kZVBvaW50ID0gKHdvcmRzW2kgPj4+IDJdID4+PiAoMTYgLSAoaSAlIDQpICogOCkpICYgMHhmZmZmO1xuXHQgICAgICAgICAgICAgICAgdXRmMTZDaGFycy5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUoY29kZVBvaW50KSk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gdXRmMTZDaGFycy5qb2luKCcnKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBVVEYtMTYgQkUgc3RyaW5nIHRvIGEgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSB1dGYxNlN0ciBUaGUgVVRGLTE2IEJFIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5lbmMuVXRmMTYucGFyc2UodXRmMTZTdHJpbmcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHBhcnNlOiBmdW5jdGlvbiAodXRmMTZTdHIpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIHV0ZjE2U3RyTGVuZ3RoID0gdXRmMTZTdHIubGVuZ3RoO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdXRmMTZTdHJMZW5ndGg7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbaSA+Pj4gMV0gfD0gdXRmMTZTdHIuY2hhckNvZGVBdChpKSA8PCAoMTYgLSAoaSAlIDIpICogMTYpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIFdvcmRBcnJheS5jcmVhdGUod29yZHMsIHV0ZjE2U3RyTGVuZ3RoICogMik7XG5cdCAgICAgICAgfVxuXHQgICAgfTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBVVEYtMTYgTEUgZW5jb2Rpbmcgc3RyYXRlZ3kuXG5cdCAgICAgKi9cblx0ICAgIENfZW5jLlV0ZjE2TEUgPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSB3b3JkIGFycmF5IHRvIGEgVVRGLTE2IExFIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSB3b3JkQXJyYXkgVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBVVEYtMTYgTEUgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgdXRmMTZTdHIgPSBDcnlwdG9KUy5lbmMuVXRmMTZMRS5zdHJpbmdpZnkod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBzdHJpbmdpZnk6IGZ1bmN0aW9uICh3b3JkQXJyYXkpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IHdvcmRBcnJheS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHNpZ0J5dGVzID0gd29yZEFycmF5LnNpZ0J5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIHV0ZjE2Q2hhcnMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzaWdCeXRlczsgaSArPSAyKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgY29kZVBvaW50ID0gc3dhcEVuZGlhbigod29yZHNbaSA+Pj4gMl0gPj4+ICgxNiAtIChpICUgNCkgKiA4KSkgJiAweGZmZmYpO1xuXHQgICAgICAgICAgICAgICAgdXRmMTZDaGFycy5wdXNoKFN0cmluZy5mcm9tQ2hhckNvZGUoY29kZVBvaW50KSk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gdXRmMTZDaGFycy5qb2luKCcnKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBVVEYtMTYgTEUgc3RyaW5nIHRvIGEgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSB1dGYxNlN0ciBUaGUgVVRGLTE2IExFIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5lbmMuVXRmMTZMRS5wYXJzZSh1dGYxNlN0cik7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcGFyc2U6IGZ1bmN0aW9uICh1dGYxNlN0cikge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgdXRmMTZTdHJMZW5ndGggPSB1dGYxNlN0ci5sZW5ndGg7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydFxuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB1dGYxNlN0ckxlbmd0aDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICB3b3Jkc1tpID4+PiAxXSB8PSBzd2FwRW5kaWFuKHV0ZjE2U3RyLmNoYXJDb2RlQXQoaSkgPDwgKDE2IC0gKGkgJSAyKSAqIDE2KSk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gV29yZEFycmF5LmNyZWF0ZSh3b3JkcywgdXRmMTZTdHJMZW5ndGggKiAyKTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICBmdW5jdGlvbiBzd2FwRW5kaWFuKHdvcmQpIHtcblx0ICAgICAgICByZXR1cm4gKCh3b3JkIDw8IDgpICYgMHhmZjAwZmYwMCkgfCAoKHdvcmQgPj4+IDgpICYgMHgwMGZmMDBmZik7XG5cdCAgICB9XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuZW5jLlV0ZjE2O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL3NoYTFcIiksIHJlcXVpcmUoXCIuL2htYWNcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vc2hhMVwiLCBcIi4vaG1hY1wiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uICgpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIEJhc2UgPSBDX2xpYi5CYXNlO1xuXHQgICAgdmFyIFdvcmRBcnJheSA9IENfbGliLldvcmRBcnJheTtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cdCAgICB2YXIgTUQ1ID0gQ19hbGdvLk1ENTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBUaGlzIGtleSBkZXJpdmF0aW9uIGZ1bmN0aW9uIGlzIG1lYW50IHRvIGNvbmZvcm0gd2l0aCBFVlBfQnl0ZXNUb0tleS5cblx0ICAgICAqIHd3dy5vcGVuc3NsLm9yZy9kb2NzL2NyeXB0by9FVlBfQnl0ZXNUb0tleS5odG1sXG5cdCAgICAgKi9cblx0ICAgIHZhciBFdnBLREYgPSBDX2FsZ28uRXZwS0RGID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmZpZ3VyYXRpb24gb3B0aW9ucy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBrZXlTaXplIFRoZSBrZXkgc2l6ZSBpbiB3b3JkcyB0byBnZW5lcmF0ZS4gRGVmYXVsdDogNCAoMTI4IGJpdHMpXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtIYXNoZXJ9IGhhc2hlciBUaGUgaGFzaCBhbGdvcml0aG0gdG8gdXNlLiBEZWZhdWx0OiBNRDVcblx0ICAgICAgICAgKiBAcHJvcGVydHkge251bWJlcn0gaXRlcmF0aW9ucyBUaGUgbnVtYmVyIG9mIGl0ZXJhdGlvbnMgdG8gcGVyZm9ybS4gRGVmYXVsdDogMVxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNmZzogQmFzZS5leHRlbmQoe1xuXHQgICAgICAgICAgICBrZXlTaXplOiAxMjgvMzIsXG5cdCAgICAgICAgICAgIGhhc2hlcjogTUQ1LFxuXHQgICAgICAgICAgICBpdGVyYXRpb25zOiAxXG5cdCAgICAgICAgfSksXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQga2V5IGRlcml2YXRpb24gZnVuY3Rpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoZSBkZXJpdmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIga2RmID0gQ3J5cHRvSlMuYWxnby5FdnBLREYuY3JlYXRlKCk7XG5cdCAgICAgICAgICogICAgIHZhciBrZGYgPSBDcnlwdG9KUy5hbGdvLkV2cEtERi5jcmVhdGUoeyBrZXlTaXplOiA4IH0pO1xuXHQgICAgICAgICAqICAgICB2YXIga2RmID0gQ3J5cHRvSlMuYWxnby5FdnBLREYuY3JlYXRlKHsga2V5U2l6ZTogOCwgaXRlcmF0aW9uczogMTAwMCB9KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoY2ZnKSB7XG5cdCAgICAgICAgICAgIHRoaXMuY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIERlcml2ZXMgYSBrZXkgZnJvbSBhIHBhc3N3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBzYWx0IEEgc2FsdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGRlcml2ZWQga2V5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIga2V5ID0ga2RmLmNvbXB1dGUocGFzc3dvcmQsIHNhbHQpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNvbXB1dGU6IGZ1bmN0aW9uIChwYXNzd29yZCwgc2FsdCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgY2ZnID0gdGhpcy5jZmc7XG5cblx0ICAgICAgICAgICAgLy8gSW5pdCBoYXNoZXJcblx0ICAgICAgICAgICAgdmFyIGhhc2hlciA9IGNmZy5oYXNoZXIuY3JlYXRlKCk7XG5cblx0ICAgICAgICAgICAgLy8gSW5pdGlhbCB2YWx1ZXNcblx0ICAgICAgICAgICAgdmFyIGRlcml2ZWRLZXkgPSBXb3JkQXJyYXkuY3JlYXRlKCk7XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkZXJpdmVkS2V5V29yZHMgPSBkZXJpdmVkS2V5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIga2V5U2l6ZSA9IGNmZy5rZXlTaXplO1xuXHQgICAgICAgICAgICB2YXIgaXRlcmF0aW9ucyA9IGNmZy5pdGVyYXRpb25zO1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGtleVxuXHQgICAgICAgICAgICB3aGlsZSAoZGVyaXZlZEtleVdvcmRzLmxlbmd0aCA8IGtleVNpemUpIHtcblx0ICAgICAgICAgICAgICAgIGlmIChibG9jaykge1xuXHQgICAgICAgICAgICAgICAgICAgIGhhc2hlci51cGRhdGUoYmxvY2spO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgdmFyIGJsb2NrID0gaGFzaGVyLnVwZGF0ZShwYXNzd29yZCkuZmluYWxpemUoc2FsdCk7XG5cdCAgICAgICAgICAgICAgICBoYXNoZXIucmVzZXQoKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gSXRlcmF0aW9uc1xuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDE7IGkgPCBpdGVyYXRpb25zOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgICAgICBibG9jayA9IGhhc2hlci5maW5hbGl6ZShibG9jayk7XG5cdCAgICAgICAgICAgICAgICAgICAgaGFzaGVyLnJlc2V0KCk7XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIGRlcml2ZWRLZXkuY29uY2F0KGJsb2NrKTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICBkZXJpdmVkS2V5LnNpZ0J5dGVzID0ga2V5U2l6ZSAqIDQ7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGRlcml2ZWRLZXk7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogRGVyaXZlcyBhIGtleSBmcm9tIGEgcGFzc3dvcmQuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQuXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IHNhbHQgQSBzYWx0LlxuXHQgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIGNvbXB1dGF0aW9uLlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGRlcml2ZWQga2V5LlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIga2V5ID0gQ3J5cHRvSlMuRXZwS0RGKHBhc3N3b3JkLCBzYWx0KTtcblx0ICAgICAqICAgICB2YXIga2V5ID0gQ3J5cHRvSlMuRXZwS0RGKHBhc3N3b3JkLCBzYWx0LCB7IGtleVNpemU6IDggfSk7XG5cdCAgICAgKiAgICAgdmFyIGtleSA9IENyeXB0b0pTLkV2cEtERihwYXNzd29yZCwgc2FsdCwgeyBrZXlTaXplOiA4LCBpdGVyYXRpb25zOiAxMDAwIH0pO1xuXHQgICAgICovXG5cdCAgICBDLkV2cEtERiA9IGZ1bmN0aW9uIChwYXNzd29yZCwgc2FsdCwgY2ZnKSB7XG5cdCAgICAgICAgcmV0dXJuIEV2cEtERi5jcmVhdGUoY2ZnKS5jb21wdXRlKHBhc3N3b3JkLCBzYWx0KTtcblx0ICAgIH07XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuRXZwS0RGO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NpcGhlci1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKHVuZGVmaW5lZCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgQ2lwaGVyUGFyYW1zID0gQ19saWIuQ2lwaGVyUGFyYW1zO1xuXHQgICAgdmFyIENfZW5jID0gQy5lbmM7XG5cdCAgICB2YXIgSGV4ID0gQ19lbmMuSGV4O1xuXHQgICAgdmFyIENfZm9ybWF0ID0gQy5mb3JtYXQ7XG5cblx0ICAgIHZhciBIZXhGb3JtYXR0ZXIgPSBDX2Zvcm1hdC5IZXggPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgdGhlIGNpcGhlcnRleHQgb2YgYSBjaXBoZXIgcGFyYW1zIG9iamVjdCB0byBhIGhleGFkZWNpbWFsbHkgZW5jb2RlZCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0NpcGhlclBhcmFtc30gY2lwaGVyUGFyYW1zIFRoZSBjaXBoZXIgcGFyYW1zIG9iamVjdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge3N0cmluZ30gVGhlIGhleGFkZWNpbWFsbHkgZW5jb2RlZCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBoZXhTdHJpbmcgPSBDcnlwdG9KUy5mb3JtYXQuSGV4LnN0cmluZ2lmeShjaXBoZXJQYXJhbXMpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHN0cmluZ2lmeTogZnVuY3Rpb24gKGNpcGhlclBhcmFtcykge1xuXHQgICAgICAgICAgICByZXR1cm4gY2lwaGVyUGFyYW1zLmNpcGhlcnRleHQudG9TdHJpbmcoSGV4KTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBoZXhhZGVjaW1hbGx5IGVuY29kZWQgY2lwaGVydGV4dCBzdHJpbmcgdG8gYSBjaXBoZXIgcGFyYW1zIG9iamVjdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSBpbnB1dCBUaGUgaGV4YWRlY2ltYWxseSBlbmNvZGVkIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0NpcGhlclBhcmFtc30gVGhlIGNpcGhlciBwYXJhbXMgb2JqZWN0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVyUGFyYW1zID0gQ3J5cHRvSlMuZm9ybWF0LkhleC5wYXJzZShoZXhTdHJpbmcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHBhcnNlOiBmdW5jdGlvbiAoaW5wdXQpIHtcblx0ICAgICAgICAgICAgdmFyIGNpcGhlcnRleHQgPSBIZXgucGFyc2UoaW5wdXQpO1xuXHQgICAgICAgICAgICByZXR1cm4gQ2lwaGVyUGFyYW1zLmNyZWF0ZSh7IGNpcGhlcnRleHQ6IGNpcGhlcnRleHQgfSk7XG5cdCAgICAgICAgfVxuXHQgICAgfTtcblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5mb3JtYXQuSGV4O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgQmFzZSA9IENfbGliLkJhc2U7XG5cdCAgICB2YXIgQ19lbmMgPSBDLmVuYztcblx0ICAgIHZhciBVdGY4ID0gQ19lbmMuVXRmODtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cblx0ICAgIC8qKlxuXHQgICAgICogSE1BQyBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBITUFDID0gQ19hbGdvLkhNQUMgPSBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogSW5pdGlhbGl6ZXMgYSBuZXdseSBjcmVhdGVkIEhNQUMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0hhc2hlcn0gaGFzaGVyIFRoZSBoYXNoIGFsZ29yaXRobSB0byB1c2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBrZXkgVGhlIHNlY3JldCBrZXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBobWFjSGFzaGVyID0gQ3J5cHRvSlMuYWxnby5ITUFDLmNyZWF0ZShDcnlwdG9KUy5hbGdvLlNIQTI1Niwga2V5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoaGFzaGVyLCBrZXkpIHtcblx0ICAgICAgICAgICAgLy8gSW5pdCBoYXNoZXJcblx0ICAgICAgICAgICAgaGFzaGVyID0gdGhpcy5faGFzaGVyID0gbmV3IGhhc2hlci5pbml0KCk7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydCBzdHJpbmcgdG8gV29yZEFycmF5LCBlbHNlIGFzc3VtZSBXb3JkQXJyYXkgYWxyZWFkeVxuXHQgICAgICAgICAgICBpZiAodHlwZW9mIGtleSA9PSAnc3RyaW5nJykge1xuXHQgICAgICAgICAgICAgICAga2V5ID0gVXRmOC5wYXJzZShrZXkpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBoYXNoZXJCbG9ja1NpemUgPSBoYXNoZXIuYmxvY2tTaXplO1xuXHQgICAgICAgICAgICB2YXIgaGFzaGVyQmxvY2tTaXplQnl0ZXMgPSBoYXNoZXJCbG9ja1NpemUgKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIEFsbG93IGFyYml0cmFyeSBsZW5ndGgga2V5c1xuXHQgICAgICAgICAgICBpZiAoa2V5LnNpZ0J5dGVzID4gaGFzaGVyQmxvY2tTaXplQnl0ZXMpIHtcblx0ICAgICAgICAgICAgICAgIGtleSA9IGhhc2hlci5maW5hbGl6ZShrZXkpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gQ2xhbXAgZXhjZXNzIGJpdHNcblx0ICAgICAgICAgICAga2V5LmNsYW1wKCk7XG5cblx0ICAgICAgICAgICAgLy8gQ2xvbmUga2V5IGZvciBpbm5lciBhbmQgb3V0ZXIgcGFkc1xuXHQgICAgICAgICAgICB2YXIgb0tleSA9IHRoaXMuX29LZXkgPSBrZXkuY2xvbmUoKTtcblx0ICAgICAgICAgICAgdmFyIGlLZXkgPSB0aGlzLl9pS2V5ID0ga2V5LmNsb25lKCk7XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBvS2V5V29yZHMgPSBvS2V5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgaUtleVdvcmRzID0gaUtleS53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBYT1Iga2V5cyB3aXRoIHBhZCBjb25zdGFudHNcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBoYXNoZXJCbG9ja1NpemU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgb0tleVdvcmRzW2ldIF49IDB4NWM1YzVjNWM7XG5cdCAgICAgICAgICAgICAgICBpS2V5V29yZHNbaV0gXj0gMHgzNjM2MzYzNjtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICBvS2V5LnNpZ0J5dGVzID0gaUtleS5zaWdCeXRlcyA9IGhhc2hlckJsb2NrU2l6ZUJ5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIFNldCBpbml0aWFsIHZhbHVlc1xuXHQgICAgICAgICAgICB0aGlzLnJlc2V0KCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFJlc2V0cyB0aGlzIEhNQUMgdG8gaXRzIGluaXRpYWwgc3RhdGUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIGhtYWNIYXNoZXIucmVzZXQoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICByZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgaGFzaGVyID0gdGhpcy5faGFzaGVyO1xuXG5cdCAgICAgICAgICAgIC8vIFJlc2V0XG5cdCAgICAgICAgICAgIGhhc2hlci5yZXNldCgpO1xuXHQgICAgICAgICAgICBoYXNoZXIudXBkYXRlKHRoaXMuX2lLZXkpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBVcGRhdGVzIHRoaXMgSE1BQyB3aXRoIGEgbWVzc2FnZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZVVwZGF0ZSBUaGUgbWVzc2FnZSB0byBhcHBlbmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtITUFDfSBUaGlzIEhNQUMgaW5zdGFuY2UuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIGhtYWNIYXNoZXIudXBkYXRlKCdtZXNzYWdlJyk7XG5cdCAgICAgICAgICogICAgIGhtYWNIYXNoZXIudXBkYXRlKHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgdXBkYXRlOiBmdW5jdGlvbiAobWVzc2FnZVVwZGF0ZSkge1xuXHQgICAgICAgICAgICB0aGlzLl9oYXNoZXIudXBkYXRlKG1lc3NhZ2VVcGRhdGUpO1xuXG5cdCAgICAgICAgICAgIC8vIENoYWluYWJsZVxuXHQgICAgICAgICAgICByZXR1cm4gdGhpcztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogRmluYWxpemVzIHRoZSBITUFDIGNvbXB1dGF0aW9uLlxuXHQgICAgICAgICAqIE5vdGUgdGhhdCB0aGUgZmluYWxpemUgb3BlcmF0aW9uIGlzIGVmZmVjdGl2ZWx5IGEgZGVzdHJ1Y3RpdmUsIHJlYWQtb25jZSBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2VVcGRhdGUgKE9wdGlvbmFsKSBBIGZpbmFsIG1lc3NhZ2UgdXBkYXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgSE1BQy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGhtYWMgPSBobWFjSGFzaGVyLmZpbmFsaXplKCk7XG5cdCAgICAgICAgICogICAgIHZhciBobWFjID0gaG1hY0hhc2hlci5maW5hbGl6ZSgnbWVzc2FnZScpO1xuXHQgICAgICAgICAqICAgICB2YXIgaG1hYyA9IGhtYWNIYXNoZXIuZmluYWxpemUod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBmaW5hbGl6ZTogZnVuY3Rpb24gKG1lc3NhZ2VVcGRhdGUpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGhhc2hlciA9IHRoaXMuX2hhc2hlcjtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRlIEhNQUNcblx0ICAgICAgICAgICAgdmFyIGlubmVySGFzaCA9IGhhc2hlci5maW5hbGl6ZShtZXNzYWdlVXBkYXRlKTtcblx0ICAgICAgICAgICAgaGFzaGVyLnJlc2V0KCk7XG5cdCAgICAgICAgICAgIHZhciBobWFjID0gaGFzaGVyLmZpbmFsaXplKHRoaXMuX29LZXkuY2xvbmUoKS5jb25jYXQoaW5uZXJIYXNoKSk7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGhtYWM7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cdH0oKSk7XG5cblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi94NjQtY29yZVwiKSwgcmVxdWlyZShcIi4vbGliLXR5cGVkYXJyYXlzXCIpLCByZXF1aXJlKFwiLi9lbmMtdXRmMTZcIiksIHJlcXVpcmUoXCIuL2VuYy1iYXNlNjRcIiksIHJlcXVpcmUoXCIuL21kNVwiKSwgcmVxdWlyZShcIi4vc2hhMVwiKSwgcmVxdWlyZShcIi4vc2hhMjU2XCIpLCByZXF1aXJlKFwiLi9zaGEyMjRcIiksIHJlcXVpcmUoXCIuL3NoYTUxMlwiKSwgcmVxdWlyZShcIi4vc2hhMzg0XCIpLCByZXF1aXJlKFwiLi9zaGEzXCIpLCByZXF1aXJlKFwiLi9yaXBlbWQxNjBcIiksIHJlcXVpcmUoXCIuL2htYWNcIiksIHJlcXVpcmUoXCIuL3Bia2RmMlwiKSwgcmVxdWlyZShcIi4vZXZwa2RmXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSwgcmVxdWlyZShcIi4vbW9kZS1jZmJcIiksIHJlcXVpcmUoXCIuL21vZGUtY3RyXCIpLCByZXF1aXJlKFwiLi9tb2RlLWN0ci1nbGFkbWFuXCIpLCByZXF1aXJlKFwiLi9tb2RlLW9mYlwiKSwgcmVxdWlyZShcIi4vbW9kZS1lY2JcIiksIHJlcXVpcmUoXCIuL3BhZC1hbnNpeDkyM1wiKSwgcmVxdWlyZShcIi4vcGFkLWlzbzEwMTI2XCIpLCByZXF1aXJlKFwiLi9wYWQtaXNvOTc5NzFcIiksIHJlcXVpcmUoXCIuL3BhZC16ZXJvcGFkZGluZ1wiKSwgcmVxdWlyZShcIi4vcGFkLW5vcGFkZGluZ1wiKSwgcmVxdWlyZShcIi4vZm9ybWF0LWhleFwiKSwgcmVxdWlyZShcIi4vYWVzXCIpLCByZXF1aXJlKFwiLi90cmlwbGVkZXNcIiksIHJlcXVpcmUoXCIuL3JjNFwiKSwgcmVxdWlyZShcIi4vcmFiYml0XCIpLCByZXF1aXJlKFwiLi9yYWJiaXQtbGVnYWN5XCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL3g2NC1jb3JlXCIsIFwiLi9saWItdHlwZWRhcnJheXNcIiwgXCIuL2VuYy11dGYxNlwiLCBcIi4vZW5jLWJhc2U2NFwiLCBcIi4vbWQ1XCIsIFwiLi9zaGExXCIsIFwiLi9zaGEyNTZcIiwgXCIuL3NoYTIyNFwiLCBcIi4vc2hhNTEyXCIsIFwiLi9zaGEzODRcIiwgXCIuL3NoYTNcIiwgXCIuL3JpcGVtZDE2MFwiLCBcIi4vaG1hY1wiLCBcIi4vcGJrZGYyXCIsIFwiLi9ldnBrZGZcIiwgXCIuL2NpcGhlci1jb3JlXCIsIFwiLi9tb2RlLWNmYlwiLCBcIi4vbW9kZS1jdHJcIiwgXCIuL21vZGUtY3RyLWdsYWRtYW5cIiwgXCIuL21vZGUtb2ZiXCIsIFwiLi9tb2RlLWVjYlwiLCBcIi4vcGFkLWFuc2l4OTIzXCIsIFwiLi9wYWQtaXNvMTAxMjZcIiwgXCIuL3BhZC1pc285Nzk3MVwiLCBcIi4vcGFkLXplcm9wYWRkaW5nXCIsIFwiLi9wYWQtbm9wYWRkaW5nXCIsIFwiLi9mb3JtYXQtaGV4XCIsIFwiLi9hZXNcIiwgXCIuL3RyaXBsZWRlc1wiLCBcIi4vcmM0XCIsIFwiLi9yYWJiaXRcIiwgXCIuL3JhYmJpdC1sZWdhY3lcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRyb290LkNyeXB0b0pTID0gZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHRyZXR1cm4gQ3J5cHRvSlM7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5KSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBDaGVjayBpZiB0eXBlZCBhcnJheXMgYXJlIHN1cHBvcnRlZFxuXHQgICAgaWYgKHR5cGVvZiBBcnJheUJ1ZmZlciAhPSAnZnVuY3Rpb24nKSB7XG5cdCAgICAgICAgcmV0dXJuO1xuXHQgICAgfVxuXG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cblx0ICAgIC8vIFJlZmVyZW5jZSBvcmlnaW5hbCBpbml0XG5cdCAgICB2YXIgc3VwZXJJbml0ID0gV29yZEFycmF5LmluaXQ7XG5cblx0ICAgIC8vIEF1Z21lbnQgV29yZEFycmF5LmluaXQgdG8gaGFuZGxlIHR5cGVkIGFycmF5c1xuXHQgICAgdmFyIHN1YkluaXQgPSBXb3JkQXJyYXkuaW5pdCA9IGZ1bmN0aW9uICh0eXBlZEFycmF5KSB7XG5cdCAgICAgICAgLy8gQ29udmVydCBidWZmZXJzIHRvIHVpbnQ4XG5cdCAgICAgICAgaWYgKHR5cGVkQXJyYXkgaW5zdGFuY2VvZiBBcnJheUJ1ZmZlcikge1xuXHQgICAgICAgICAgICB0eXBlZEFycmF5ID0gbmV3IFVpbnQ4QXJyYXkodHlwZWRBcnJheSk7XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gQ29udmVydCBvdGhlciBhcnJheSB2aWV3cyB0byB1aW50OFxuXHQgICAgICAgIGlmIChcblx0ICAgICAgICAgICAgdHlwZWRBcnJheSBpbnN0YW5jZW9mIEludDhBcnJheSB8fFxuXHQgICAgICAgICAgICAodHlwZW9mIFVpbnQ4Q2xhbXBlZEFycmF5ICE9PSBcInVuZGVmaW5lZFwiICYmIHR5cGVkQXJyYXkgaW5zdGFuY2VvZiBVaW50OENsYW1wZWRBcnJheSkgfHxcblx0ICAgICAgICAgICAgdHlwZWRBcnJheSBpbnN0YW5jZW9mIEludDE2QXJyYXkgfHxcblx0ICAgICAgICAgICAgdHlwZWRBcnJheSBpbnN0YW5jZW9mIFVpbnQxNkFycmF5IHx8XG5cdCAgICAgICAgICAgIHR5cGVkQXJyYXkgaW5zdGFuY2VvZiBJbnQzMkFycmF5IHx8XG5cdCAgICAgICAgICAgIHR5cGVkQXJyYXkgaW5zdGFuY2VvZiBVaW50MzJBcnJheSB8fFxuXHQgICAgICAgICAgICB0eXBlZEFycmF5IGluc3RhbmNlb2YgRmxvYXQzMkFycmF5IHx8XG5cdCAgICAgICAgICAgIHR5cGVkQXJyYXkgaW5zdGFuY2VvZiBGbG9hdDY0QXJyYXlcblx0ICAgICAgICApIHtcblx0ICAgICAgICAgICAgdHlwZWRBcnJheSA9IG5ldyBVaW50OEFycmF5KHR5cGVkQXJyYXkuYnVmZmVyLCB0eXBlZEFycmF5LmJ5dGVPZmZzZXQsIHR5cGVkQXJyYXkuYnl0ZUxlbmd0aCk7XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gSGFuZGxlIFVpbnQ4QXJyYXlcblx0ICAgICAgICBpZiAodHlwZWRBcnJheSBpbnN0YW5jZW9mIFVpbnQ4QXJyYXkpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIHR5cGVkQXJyYXlCeXRlTGVuZ3RoID0gdHlwZWRBcnJheS5ieXRlTGVuZ3RoO1xuXG5cdCAgICAgICAgICAgIC8vIEV4dHJhY3QgYnl0ZXNcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdHlwZWRBcnJheUJ5dGVMZW5ndGg7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbaSA+Pj4gMl0gfD0gdHlwZWRBcnJheVtpXSA8PCAoMjQgLSAoaSAlIDQpICogOCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBJbml0aWFsaXplIHRoaXMgd29yZCBhcnJheVxuXHQgICAgICAgICAgICBzdXBlckluaXQuY2FsbCh0aGlzLCB3b3JkcywgdHlwZWRBcnJheUJ5dGVMZW5ndGgpO1xuXHQgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgIC8vIEVsc2UgY2FsbCBub3JtYWwgaW5pdFxuXHQgICAgICAgICAgICBzdXBlckluaXQuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICBzdWJJbml0LnByb3RvdHlwZSA9IFdvcmRBcnJheTtcblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5saWIuV29yZEFycmF5O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKE1hdGgpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIFdvcmRBcnJheSA9IENfbGliLldvcmRBcnJheTtcblx0ICAgIHZhciBIYXNoZXIgPSBDX2xpYi5IYXNoZXI7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICAvLyBDb25zdGFudHMgdGFibGVcblx0ICAgIHZhciBUID0gW107XG5cblx0ICAgIC8vIENvbXB1dGUgY29uc3RhbnRzXG5cdCAgICAoZnVuY3Rpb24gKCkge1xuXHQgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgNjQ7IGkrKykge1xuXHQgICAgICAgICAgICBUW2ldID0gKE1hdGguYWJzKE1hdGguc2luKGkgKyAxKSkgKiAweDEwMDAwMDAwMCkgfCAwO1xuXHQgICAgICAgIH1cblx0ICAgIH0oKSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogTUQ1IGhhc2ggYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgTUQ1ID0gQ19hbGdvLk1ENSA9IEhhc2hlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHRoaXMuX2hhc2ggPSBuZXcgV29yZEFycmF5LmluaXQoW1xuXHQgICAgICAgICAgICAgICAgMHg2NzQ1MjMwMSwgMHhlZmNkYWI4OSxcblx0ICAgICAgICAgICAgICAgIDB4OThiYWRjZmUsIDB4MTAzMjU0NzZcblx0ICAgICAgICAgICAgXSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTd2FwIGVuZGlhblxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDE2OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgdmFyIG9mZnNldF9pID0gb2Zmc2V0ICsgaTtcblx0ICAgICAgICAgICAgICAgIHZhciBNX29mZnNldF9pID0gTVtvZmZzZXRfaV07XG5cblx0ICAgICAgICAgICAgICAgIE1bb2Zmc2V0X2ldID0gKFxuXHQgICAgICAgICAgICAgICAgICAgICgoKE1fb2Zmc2V0X2kgPDwgOCkgIHwgKE1fb2Zmc2V0X2kgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8XG5cdCAgICAgICAgICAgICAgICAgICAgKCgoTV9vZmZzZXRfaSA8PCAyNCkgfCAoTV9vZmZzZXRfaSA+Pj4gOCkpICAmIDB4ZmYwMGZmMDApXG5cdCAgICAgICAgICAgICAgICApO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBIID0gdGhpcy5faGFzaC53b3JkcztcblxuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMCAgPSBNW29mZnNldCArIDBdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMSAgPSBNW29mZnNldCArIDFdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMiAgPSBNW29mZnNldCArIDJdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMyAgPSBNW29mZnNldCArIDNdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfNCAgPSBNW29mZnNldCArIDRdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfNSAgPSBNW29mZnNldCArIDVdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfNiAgPSBNW29mZnNldCArIDZdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfNyAgPSBNW29mZnNldCArIDddO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfOCAgPSBNW29mZnNldCArIDhdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfOSAgPSBNW29mZnNldCArIDldO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMTAgPSBNW29mZnNldCArIDEwXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzExID0gTVtvZmZzZXQgKyAxMV07XG5cdCAgICAgICAgICAgIHZhciBNX29mZnNldF8xMiA9IE1bb2Zmc2V0ICsgMTJdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMTMgPSBNW29mZnNldCArIDEzXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzE0ID0gTVtvZmZzZXQgKyAxNF07XG5cdCAgICAgICAgICAgIHZhciBNX29mZnNldF8xNSA9IE1bb2Zmc2V0ICsgMTVdO1xuXG5cdCAgICAgICAgICAgIC8vIFdvcmtpbmcgdmFyaWFsYmVzXG5cdCAgICAgICAgICAgIHZhciBhID0gSFswXTtcblx0ICAgICAgICAgICAgdmFyIGIgPSBIWzFdO1xuXHQgICAgICAgICAgICB2YXIgYyA9IEhbMl07XG5cdCAgICAgICAgICAgIHZhciBkID0gSFszXTtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRhdGlvblxuXHQgICAgICAgICAgICBhID0gRkYoYSwgYiwgYywgZCwgTV9vZmZzZXRfMCwgIDcsICBUWzBdKTtcblx0ICAgICAgICAgICAgZCA9IEZGKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzEsICAxMiwgVFsxXSk7XG5cdCAgICAgICAgICAgIGMgPSBGRihjLCBkLCBhLCBiLCBNX29mZnNldF8yLCAgMTcsIFRbMl0pO1xuXHQgICAgICAgICAgICBiID0gRkYoYiwgYywgZCwgYSwgTV9vZmZzZXRfMywgIDIyLCBUWzNdKTtcblx0ICAgICAgICAgICAgYSA9IEZGKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzQsICA3LCAgVFs0XSk7XG5cdCAgICAgICAgICAgIGQgPSBGRihkLCBhLCBiLCBjLCBNX29mZnNldF81LCAgMTIsIFRbNV0pO1xuXHQgICAgICAgICAgICBjID0gRkYoYywgZCwgYSwgYiwgTV9vZmZzZXRfNiwgIDE3LCBUWzZdKTtcblx0ICAgICAgICAgICAgYiA9IEZGKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzcsICAyMiwgVFs3XSk7XG5cdCAgICAgICAgICAgIGEgPSBGRihhLCBiLCBjLCBkLCBNX29mZnNldF84LCAgNywgIFRbOF0pO1xuXHQgICAgICAgICAgICBkID0gRkYoZCwgYSwgYiwgYywgTV9vZmZzZXRfOSwgIDEyLCBUWzldKTtcblx0ICAgICAgICAgICAgYyA9IEZGKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzEwLCAxNywgVFsxMF0pO1xuXHQgICAgICAgICAgICBiID0gRkYoYiwgYywgZCwgYSwgTV9vZmZzZXRfMTEsIDIyLCBUWzExXSk7XG5cdCAgICAgICAgICAgIGEgPSBGRihhLCBiLCBjLCBkLCBNX29mZnNldF8xMiwgNywgIFRbMTJdKTtcblx0ICAgICAgICAgICAgZCA9IEZGKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzEzLCAxMiwgVFsxM10pO1xuXHQgICAgICAgICAgICBjID0gRkYoYywgZCwgYSwgYiwgTV9vZmZzZXRfMTQsIDE3LCBUWzE0XSk7XG5cdCAgICAgICAgICAgIGIgPSBGRihiLCBjLCBkLCBhLCBNX29mZnNldF8xNSwgMjIsIFRbMTVdKTtcblxuXHQgICAgICAgICAgICBhID0gR0coYSwgYiwgYywgZCwgTV9vZmZzZXRfMSwgIDUsICBUWzE2XSk7XG5cdCAgICAgICAgICAgIGQgPSBHRyhkLCBhLCBiLCBjLCBNX29mZnNldF82LCAgOSwgIFRbMTddKTtcblx0ICAgICAgICAgICAgYyA9IEdHKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzExLCAxNCwgVFsxOF0pO1xuXHQgICAgICAgICAgICBiID0gR0coYiwgYywgZCwgYSwgTV9vZmZzZXRfMCwgIDIwLCBUWzE5XSk7XG5cdCAgICAgICAgICAgIGEgPSBHRyhhLCBiLCBjLCBkLCBNX29mZnNldF81LCAgNSwgIFRbMjBdKTtcblx0ICAgICAgICAgICAgZCA9IEdHKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzEwLCA5LCAgVFsyMV0pO1xuXHQgICAgICAgICAgICBjID0gR0coYywgZCwgYSwgYiwgTV9vZmZzZXRfMTUsIDE0LCBUWzIyXSk7XG5cdCAgICAgICAgICAgIGIgPSBHRyhiLCBjLCBkLCBhLCBNX29mZnNldF80LCAgMjAsIFRbMjNdKTtcblx0ICAgICAgICAgICAgYSA9IEdHKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzksICA1LCAgVFsyNF0pO1xuXHQgICAgICAgICAgICBkID0gR0coZCwgYSwgYiwgYywgTV9vZmZzZXRfMTQsIDksICBUWzI1XSk7XG5cdCAgICAgICAgICAgIGMgPSBHRyhjLCBkLCBhLCBiLCBNX29mZnNldF8zLCAgMTQsIFRbMjZdKTtcblx0ICAgICAgICAgICAgYiA9IEdHKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzgsICAyMCwgVFsyN10pO1xuXHQgICAgICAgICAgICBhID0gR0coYSwgYiwgYywgZCwgTV9vZmZzZXRfMTMsIDUsICBUWzI4XSk7XG5cdCAgICAgICAgICAgIGQgPSBHRyhkLCBhLCBiLCBjLCBNX29mZnNldF8yLCAgOSwgIFRbMjldKTtcblx0ICAgICAgICAgICAgYyA9IEdHKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzcsICAxNCwgVFszMF0pO1xuXHQgICAgICAgICAgICBiID0gR0coYiwgYywgZCwgYSwgTV9vZmZzZXRfMTIsIDIwLCBUWzMxXSk7XG5cblx0ICAgICAgICAgICAgYSA9IEhIKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzUsICA0LCAgVFszMl0pO1xuXHQgICAgICAgICAgICBkID0gSEgoZCwgYSwgYiwgYywgTV9vZmZzZXRfOCwgIDExLCBUWzMzXSk7XG5cdCAgICAgICAgICAgIGMgPSBISChjLCBkLCBhLCBiLCBNX29mZnNldF8xMSwgMTYsIFRbMzRdKTtcblx0ICAgICAgICAgICAgYiA9IEhIKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzE0LCAyMywgVFszNV0pO1xuXHQgICAgICAgICAgICBhID0gSEgoYSwgYiwgYywgZCwgTV9vZmZzZXRfMSwgIDQsICBUWzM2XSk7XG5cdCAgICAgICAgICAgIGQgPSBISChkLCBhLCBiLCBjLCBNX29mZnNldF80LCAgMTEsIFRbMzddKTtcblx0ICAgICAgICAgICAgYyA9IEhIKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzcsICAxNiwgVFszOF0pO1xuXHQgICAgICAgICAgICBiID0gSEgoYiwgYywgZCwgYSwgTV9vZmZzZXRfMTAsIDIzLCBUWzM5XSk7XG5cdCAgICAgICAgICAgIGEgPSBISChhLCBiLCBjLCBkLCBNX29mZnNldF8xMywgNCwgIFRbNDBdKTtcblx0ICAgICAgICAgICAgZCA9IEhIKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzAsICAxMSwgVFs0MV0pO1xuXHQgICAgICAgICAgICBjID0gSEgoYywgZCwgYSwgYiwgTV9vZmZzZXRfMywgIDE2LCBUWzQyXSk7XG5cdCAgICAgICAgICAgIGIgPSBISChiLCBjLCBkLCBhLCBNX29mZnNldF82LCAgMjMsIFRbNDNdKTtcblx0ICAgICAgICAgICAgYSA9IEhIKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzksICA0LCAgVFs0NF0pO1xuXHQgICAgICAgICAgICBkID0gSEgoZCwgYSwgYiwgYywgTV9vZmZzZXRfMTIsIDExLCBUWzQ1XSk7XG5cdCAgICAgICAgICAgIGMgPSBISChjLCBkLCBhLCBiLCBNX29mZnNldF8xNSwgMTYsIFRbNDZdKTtcblx0ICAgICAgICAgICAgYiA9IEhIKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzIsICAyMywgVFs0N10pO1xuXG5cdCAgICAgICAgICAgIGEgPSBJSShhLCBiLCBjLCBkLCBNX29mZnNldF8wLCAgNiwgIFRbNDhdKTtcblx0ICAgICAgICAgICAgZCA9IElJKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzcsICAxMCwgVFs0OV0pO1xuXHQgICAgICAgICAgICBjID0gSUkoYywgZCwgYSwgYiwgTV9vZmZzZXRfMTQsIDE1LCBUWzUwXSk7XG5cdCAgICAgICAgICAgIGIgPSBJSShiLCBjLCBkLCBhLCBNX29mZnNldF81LCAgMjEsIFRbNTFdKTtcblx0ICAgICAgICAgICAgYSA9IElJKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzEyLCA2LCAgVFs1Ml0pO1xuXHQgICAgICAgICAgICBkID0gSUkoZCwgYSwgYiwgYywgTV9vZmZzZXRfMywgIDEwLCBUWzUzXSk7XG5cdCAgICAgICAgICAgIGMgPSBJSShjLCBkLCBhLCBiLCBNX29mZnNldF8xMCwgMTUsIFRbNTRdKTtcblx0ICAgICAgICAgICAgYiA9IElJKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzEsICAyMSwgVFs1NV0pO1xuXHQgICAgICAgICAgICBhID0gSUkoYSwgYiwgYywgZCwgTV9vZmZzZXRfOCwgIDYsICBUWzU2XSk7XG5cdCAgICAgICAgICAgIGQgPSBJSShkLCBhLCBiLCBjLCBNX29mZnNldF8xNSwgMTAsIFRbNTddKTtcblx0ICAgICAgICAgICAgYyA9IElJKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzYsICAxNSwgVFs1OF0pO1xuXHQgICAgICAgICAgICBiID0gSUkoYiwgYywgZCwgYSwgTV9vZmZzZXRfMTMsIDIxLCBUWzU5XSk7XG5cdCAgICAgICAgICAgIGEgPSBJSShhLCBiLCBjLCBkLCBNX29mZnNldF80LCAgNiwgIFRbNjBdKTtcblx0ICAgICAgICAgICAgZCA9IElJKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzExLCAxMCwgVFs2MV0pO1xuXHQgICAgICAgICAgICBjID0gSUkoYywgZCwgYSwgYiwgTV9vZmZzZXRfMiwgIDE1LCBUWzYyXSk7XG5cdCAgICAgICAgICAgIGIgPSBJSShiLCBjLCBkLCBhLCBNX29mZnNldF85LCAgMjEsIFRbNjNdKTtcblxuXHQgICAgICAgICAgICAvLyBJbnRlcm1lZGlhdGUgaGFzaCB2YWx1ZVxuXHQgICAgICAgICAgICBIWzBdID0gKEhbMF0gKyBhKSB8IDA7XG5cdCAgICAgICAgICAgIEhbMV0gPSAoSFsxXSArIGIpIHwgMDtcblx0ICAgICAgICAgICAgSFsyXSA9IChIWzJdICsgYykgfCAwO1xuXHQgICAgICAgICAgICBIWzNdID0gKEhbM10gKyBkKSB8IDA7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0ZpbmFsaXplOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgZGF0YSA9IHRoaXMuX2RhdGE7XG5cdCAgICAgICAgICAgIHZhciBkYXRhV29yZHMgPSBkYXRhLndvcmRzO1xuXG5cdCAgICAgICAgICAgIHZhciBuQml0c1RvdGFsID0gdGhpcy5fbkRhdGFCeXRlcyAqIDg7XG5cdCAgICAgICAgICAgIHZhciBuQml0c0xlZnQgPSBkYXRhLnNpZ0J5dGVzICogODtcblxuXHQgICAgICAgICAgICAvLyBBZGQgcGFkZGluZ1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbbkJpdHNMZWZ0ID4+PiA1XSB8PSAweDgwIDw8ICgyNCAtIG5CaXRzTGVmdCAlIDMyKTtcblxuXHQgICAgICAgICAgICB2YXIgbkJpdHNUb3RhbEggPSBNYXRoLmZsb29yKG5CaXRzVG90YWwgLyAweDEwMDAwMDAwMCk7XG5cdCAgICAgICAgICAgIHZhciBuQml0c1RvdGFsTCA9IG5CaXRzVG90YWw7XG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1soKChuQml0c0xlZnQgKyA2NCkgPj4+IDkpIDw8IDQpICsgMTVdID0gKFxuXHQgICAgICAgICAgICAgICAgKCgobkJpdHNUb3RhbEggPDwgOCkgIHwgKG5CaXRzVG90YWxIID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgKCgobkJpdHNUb3RhbEggPDwgMjQpIHwgKG5CaXRzVG90YWxIID4+PiA4KSkgICYgMHhmZjAwZmYwMClcblx0ICAgICAgICAgICAgKTtcblx0ICAgICAgICAgICAgZGF0YVdvcmRzWygoKG5CaXRzTGVmdCArIDY0KSA+Pj4gOSkgPDwgNCkgKyAxNF0gPSAoXG5cdCAgICAgICAgICAgICAgICAoKChuQml0c1RvdGFsTCA8PCA4KSAgfCAobkJpdHNUb3RhbEwgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8XG5cdCAgICAgICAgICAgICAgICAoKChuQml0c1RvdGFsTCA8PCAyNCkgfCAobkJpdHNUb3RhbEwgPj4+IDgpKSAgJiAweGZmMDBmZjAwKVxuXHQgICAgICAgICAgICApO1xuXG5cdCAgICAgICAgICAgIGRhdGEuc2lnQnl0ZXMgPSAoZGF0YVdvcmRzLmxlbmd0aCArIDEpICogNDtcblxuXHQgICAgICAgICAgICAvLyBIYXNoIGZpbmFsIGJsb2Nrc1xuXHQgICAgICAgICAgICB0aGlzLl9wcm9jZXNzKCk7XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBoYXNoID0gdGhpcy5faGFzaDtcblx0ICAgICAgICAgICAgdmFyIEggPSBoYXNoLndvcmRzO1xuXG5cdCAgICAgICAgICAgIC8vIFN3YXAgZW5kaWFuXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgNDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICAgICAgdmFyIEhfaSA9IEhbaV07XG5cblx0ICAgICAgICAgICAgICAgIEhbaV0gPSAoKChIX2kgPDwgOCkgIHwgKEhfaSA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICAgICAgICAoKChIX2kgPDwgMjQpIHwgKEhfaSA+Pj4gOCkpICAmIDB4ZmYwMGZmMDApO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gUmV0dXJuIGZpbmFsIGNvbXB1dGVkIGhhc2hcblx0ICAgICAgICAgICAgcmV0dXJuIGhhc2g7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGNsb25lOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHZhciBjbG9uZSA9IEhhc2hlci5jbG9uZS5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICBjbG9uZS5faGFzaCA9IHRoaXMuX2hhc2guY2xvbmUoKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gY2xvbmU7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIGZ1bmN0aW9uIEZGKGEsIGIsIGMsIGQsIHgsIHMsIHQpIHtcblx0ICAgICAgICB2YXIgbiA9IGEgKyAoKGIgJiBjKSB8ICh+YiAmIGQpKSArIHggKyB0O1xuXHQgICAgICAgIHJldHVybiAoKG4gPDwgcykgfCAobiA+Pj4gKDMyIC0gcykpKSArIGI7XG5cdCAgICB9XG5cblx0ICAgIGZ1bmN0aW9uIEdHKGEsIGIsIGMsIGQsIHgsIHMsIHQpIHtcblx0ICAgICAgICB2YXIgbiA9IGEgKyAoKGIgJiBkKSB8IChjICYgfmQpKSArIHggKyB0O1xuXHQgICAgICAgIHJldHVybiAoKG4gPDwgcykgfCAobiA+Pj4gKDMyIC0gcykpKSArIGI7XG5cdCAgICB9XG5cblx0ICAgIGZ1bmN0aW9uIEhIKGEsIGIsIGMsIGQsIHgsIHMsIHQpIHtcblx0ICAgICAgICB2YXIgbiA9IGEgKyAoYiBeIGMgXiBkKSArIHggKyB0O1xuXHQgICAgICAgIHJldHVybiAoKG4gPDwgcykgfCAobiA+Pj4gKDMyIC0gcykpKSArIGI7XG5cdCAgICB9XG5cblx0ICAgIGZ1bmN0aW9uIElJKGEsIGIsIGMsIGQsIHgsIHMsIHQpIHtcblx0ICAgICAgICB2YXIgbiA9IGEgKyAoYyBeIChiIHwgfmQpKSArIHggKyB0O1xuXHQgICAgICAgIHJldHVybiAoKG4gPDwgcykgfCAobiA+Pj4gKDMyIC0gcykpKSArIGI7XG5cdCAgICB9XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIGhhc2hlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5NRDUoJ21lc3NhZ2UnKTtcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLk1ENSh3b3JkQXJyYXkpO1xuXHQgICAgICovXG5cdCAgICBDLk1ENSA9IEhhc2hlci5fY3JlYXRlSGVscGVyKE1ENSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIEhNQUMncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBrZXkgVGhlIHNlY3JldCBrZXkuXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgSE1BQy5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhtYWMgPSBDcnlwdG9KUy5IbWFjTUQ1KG1lc3NhZ2UsIGtleSk7XG5cdCAgICAgKi9cblx0ICAgIEMuSG1hY01ENSA9IEhhc2hlci5fY3JlYXRlSG1hY0hlbHBlcihNRDUpO1xuXHR9KE1hdGgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5NRDU7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdC8qKlxuXHQgKiBDaXBoZXIgRmVlZGJhY2sgYmxvY2sgbW9kZS5cblx0ICovXG5cdENyeXB0b0pTLm1vZGUuQ0ZCID0gKGZ1bmN0aW9uICgpIHtcblx0ICAgIHZhciBDRkIgPSBDcnlwdG9KUy5saWIuQmxvY2tDaXBoZXJNb2RlLmV4dGVuZCgpO1xuXG5cdCAgICBDRkIuRW5jcnlwdG9yID0gQ0ZCLmV4dGVuZCh7XG5cdCAgICAgICAgcHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAod29yZHMsIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGNpcGhlciA9IHRoaXMuX2NpcGhlcjtcblx0ICAgICAgICAgICAgdmFyIGJsb2NrU2l6ZSA9IGNpcGhlci5ibG9ja1NpemU7XG5cblx0ICAgICAgICAgICAgZ2VuZXJhdGVLZXlzdHJlYW1BbmRFbmNyeXB0LmNhbGwodGhpcywgd29yZHMsIG9mZnNldCwgYmxvY2tTaXplLCBjaXBoZXIpO1xuXG5cdCAgICAgICAgICAgIC8vIFJlbWVtYmVyIHRoaXMgYmxvY2sgdG8gdXNlIHdpdGggbmV4dCBibG9ja1xuXHQgICAgICAgICAgICB0aGlzLl9wcmV2QmxvY2sgPSB3b3Jkcy5zbGljZShvZmZzZXQsIG9mZnNldCArIGJsb2NrU2l6ZSk7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIENGQi5EZWNyeXB0b3IgPSBDRkIuZXh0ZW5kKHtcblx0ICAgICAgICBwcm9jZXNzQmxvY2s6IGZ1bmN0aW9uICh3b3Jkcywgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgY2lwaGVyID0gdGhpcy5fY2lwaGVyO1xuXHQgICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gY2lwaGVyLmJsb2NrU2l6ZTtcblxuXHQgICAgICAgICAgICAvLyBSZW1lbWJlciB0aGlzIGJsb2NrIHRvIHVzZSB3aXRoIG5leHQgYmxvY2tcblx0ICAgICAgICAgICAgdmFyIHRoaXNCbG9jayA9IHdvcmRzLnNsaWNlKG9mZnNldCwgb2Zmc2V0ICsgYmxvY2tTaXplKTtcblxuXHQgICAgICAgICAgICBnZW5lcmF0ZUtleXN0cmVhbUFuZEVuY3J5cHQuY2FsbCh0aGlzLCB3b3Jkcywgb2Zmc2V0LCBibG9ja1NpemUsIGNpcGhlcik7XG5cblx0ICAgICAgICAgICAgLy8gVGhpcyBibG9jayBiZWNvbWVzIHRoZSBwcmV2aW91cyBibG9ja1xuXHQgICAgICAgICAgICB0aGlzLl9wcmV2QmxvY2sgPSB0aGlzQmxvY2s7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIGZ1bmN0aW9uIGdlbmVyYXRlS2V5c3RyZWFtQW5kRW5jcnlwdCh3b3Jkcywgb2Zmc2V0LCBibG9ja1NpemUsIGNpcGhlcikge1xuXHQgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgdmFyIGl2ID0gdGhpcy5faXY7XG5cblx0ICAgICAgICAvLyBHZW5lcmF0ZSBrZXlzdHJlYW1cblx0ICAgICAgICBpZiAoaXYpIHtcblx0ICAgICAgICAgICAgdmFyIGtleXN0cmVhbSA9IGl2LnNsaWNlKDApO1xuXG5cdCAgICAgICAgICAgIC8vIFJlbW92ZSBJViBmb3Igc3Vic2VxdWVudCBibG9ja3Ncblx0ICAgICAgICAgICAgdGhpcy5faXYgPSB1bmRlZmluZWQ7XG5cdCAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgdmFyIGtleXN0cmVhbSA9IHRoaXMuX3ByZXZCbG9jaztcblx0ICAgICAgICB9XG5cdCAgICAgICAgY2lwaGVyLmVuY3J5cHRCbG9jayhrZXlzdHJlYW0sIDApO1xuXG5cdCAgICAgICAgLy8gRW5jcnlwdFxuXHQgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYmxvY2tTaXplOyBpKyspIHtcblx0ICAgICAgICAgICAgd29yZHNbb2Zmc2V0ICsgaV0gXj0ga2V5c3RyZWFtW2ldO1xuXHQgICAgICAgIH1cblx0ICAgIH1cblxuXHQgICAgcmV0dXJuIENGQjtcblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5tb2RlLkNGQjtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9jaXBoZXItY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0LyoqIEBwcmVzZXJ2ZVxuXHQgKiBDb3VudGVyIGJsb2NrIG1vZGUgY29tcGF0aWJsZSB3aXRoICBEciBCcmlhbiBHbGFkbWFuIGZpbGVlbmMuY1xuXHQgKiBkZXJpdmVkIGZyb20gQ3J5cHRvSlMubW9kZS5DVFJcblx0ICogSmFuIEhydWJ5IGpocnVieS53ZWJAZ21haWwuY29tXG5cdCAqL1xuXHRDcnlwdG9KUy5tb2RlLkNUUkdsYWRtYW4gPSAoZnVuY3Rpb24gKCkge1xuXHQgICAgdmFyIENUUkdsYWRtYW4gPSBDcnlwdG9KUy5saWIuQmxvY2tDaXBoZXJNb2RlLmV4dGVuZCgpO1xuXG5cdFx0ZnVuY3Rpb24gaW5jV29yZCh3b3JkKVxuXHRcdHtcblx0XHRcdGlmICgoKHdvcmQgPj4gMjQpICYgMHhmZikgPT09IDB4ZmYpIHsgLy9vdmVyZmxvd1xuXHRcdFx0dmFyIGIxID0gKHdvcmQgPj4gMTYpJjB4ZmY7XG5cdFx0XHR2YXIgYjIgPSAod29yZCA+PiA4KSYweGZmO1xuXHRcdFx0dmFyIGIzID0gd29yZCAmIDB4ZmY7XG5cblx0XHRcdGlmIChiMSA9PT0gMHhmZikgLy8gb3ZlcmZsb3cgYjFcblx0XHRcdHtcblx0XHRcdGIxID0gMDtcblx0XHRcdGlmIChiMiA9PT0gMHhmZilcblx0XHRcdHtcblx0XHRcdFx0YjIgPSAwO1xuXHRcdFx0XHRpZiAoYjMgPT09IDB4ZmYpXG5cdFx0XHRcdHtcblx0XHRcdFx0XHRiMyA9IDA7XG5cdFx0XHRcdH1cblx0XHRcdFx0ZWxzZVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0KytiMztcblx0XHRcdFx0fVxuXHRcdFx0fVxuXHRcdFx0ZWxzZVxuXHRcdFx0e1xuXHRcdFx0XHQrK2IyO1xuXHRcdFx0fVxuXHRcdFx0fVxuXHRcdFx0ZWxzZVxuXHRcdFx0e1xuXHRcdFx0KytiMTtcblx0XHRcdH1cblxuXHRcdFx0d29yZCA9IDA7XG5cdFx0XHR3b3JkICs9IChiMSA8PCAxNik7XG5cdFx0XHR3b3JkICs9IChiMiA8PCA4KTtcblx0XHRcdHdvcmQgKz0gYjM7XG5cdFx0XHR9XG5cdFx0XHRlbHNlXG5cdFx0XHR7XG5cdFx0XHR3b3JkICs9ICgweDAxIDw8IDI0KTtcblx0XHRcdH1cblx0XHRcdHJldHVybiB3b3JkO1xuXHRcdH1cblxuXHRcdGZ1bmN0aW9uIGluY0NvdW50ZXIoY291bnRlcilcblx0XHR7XG5cdFx0XHRpZiAoKGNvdW50ZXJbMF0gPSBpbmNXb3JkKGNvdW50ZXJbMF0pKSA9PT0gMClcblx0XHRcdHtcblx0XHRcdFx0Ly8gZW5jcl9kYXRhIGluIGZpbGVlbmMuYyBmcm9tICBEciBCcmlhbiBHbGFkbWFuJ3MgY291bnRzIG9ubHkgd2l0aCBEV09SRCBqIDwgOFxuXHRcdFx0XHRjb3VudGVyWzFdID0gaW5jV29yZChjb3VudGVyWzFdKTtcblx0XHRcdH1cblx0XHRcdHJldHVybiBjb3VudGVyO1xuXHRcdH1cblxuXHQgICAgdmFyIEVuY3J5cHRvciA9IENUUkdsYWRtYW4uRW5jcnlwdG9yID0gQ1RSR2xhZG1hbi5leHRlbmQoe1xuXHQgICAgICAgIHByb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBjaXBoZXIgPSB0aGlzLl9jaXBoZXJcblx0ICAgICAgICAgICAgdmFyIGJsb2NrU2l6ZSA9IGNpcGhlci5ibG9ja1NpemU7XG5cdCAgICAgICAgICAgIHZhciBpdiA9IHRoaXMuX2l2O1xuXHQgICAgICAgICAgICB2YXIgY291bnRlciA9IHRoaXMuX2NvdW50ZXI7XG5cblx0ICAgICAgICAgICAgLy8gR2VuZXJhdGUga2V5c3RyZWFtXG5cdCAgICAgICAgICAgIGlmIChpdikge1xuXHQgICAgICAgICAgICAgICAgY291bnRlciA9IHRoaXMuX2NvdW50ZXIgPSBpdi5zbGljZSgwKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIElWIGZvciBzdWJzZXF1ZW50IGJsb2Nrc1xuXHQgICAgICAgICAgICAgICAgdGhpcy5faXYgPSB1bmRlZmluZWQ7XG5cdCAgICAgICAgICAgIH1cblxuXHRcdFx0XHRpbmNDb3VudGVyKGNvdW50ZXIpO1xuXG5cdFx0XHRcdHZhciBrZXlzdHJlYW0gPSBjb3VudGVyLnNsaWNlKDApO1xuXHQgICAgICAgICAgICBjaXBoZXIuZW5jcnlwdEJsb2NrKGtleXN0cmVhbSwgMCk7XG5cblx0ICAgICAgICAgICAgLy8gRW5jcnlwdFxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJsb2NrU2l6ZTsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICB3b3Jkc1tvZmZzZXQgKyBpXSBePSBrZXlzdHJlYW1baV07XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgQ1RSR2xhZG1hbi5EZWNyeXB0b3IgPSBFbmNyeXB0b3I7XG5cblx0ICAgIHJldHVybiBDVFJHbGFkbWFuO1xuXHR9KCkpO1xuXG5cblxuXG5cdHJldHVybiBDcnlwdG9KUy5tb2RlLkNUUkdsYWRtYW47XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdC8qKlxuXHQgKiBDb3VudGVyIGJsb2NrIG1vZGUuXG5cdCAqL1xuXHRDcnlwdG9KUy5tb2RlLkNUUiA9IChmdW5jdGlvbiAoKSB7XG5cdCAgICB2YXIgQ1RSID0gQ3J5cHRvSlMubGliLkJsb2NrQ2lwaGVyTW9kZS5leHRlbmQoKTtcblxuXHQgICAgdmFyIEVuY3J5cHRvciA9IENUUi5FbmNyeXB0b3IgPSBDVFIuZXh0ZW5kKHtcblx0ICAgICAgICBwcm9jZXNzQmxvY2s6IGZ1bmN0aW9uICh3b3Jkcywgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgY2lwaGVyID0gdGhpcy5fY2lwaGVyXG5cdCAgICAgICAgICAgIHZhciBibG9ja1NpemUgPSBjaXBoZXIuYmxvY2tTaXplO1xuXHQgICAgICAgICAgICB2YXIgaXYgPSB0aGlzLl9pdjtcblx0ICAgICAgICAgICAgdmFyIGNvdW50ZXIgPSB0aGlzLl9jb3VudGVyO1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGtleXN0cmVhbVxuXHQgICAgICAgICAgICBpZiAoaXYpIHtcblx0ICAgICAgICAgICAgICAgIGNvdW50ZXIgPSB0aGlzLl9jb3VudGVyID0gaXYuc2xpY2UoMCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFJlbW92ZSBJViBmb3Igc3Vic2VxdWVudCBibG9ja3Ncblx0ICAgICAgICAgICAgICAgIHRoaXMuX2l2ID0gdW5kZWZpbmVkO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIHZhciBrZXlzdHJlYW0gPSBjb3VudGVyLnNsaWNlKDApO1xuXHQgICAgICAgICAgICBjaXBoZXIuZW5jcnlwdEJsb2NrKGtleXN0cmVhbSwgMCk7XG5cblx0ICAgICAgICAgICAgLy8gSW5jcmVtZW50IGNvdW50ZXJcblx0ICAgICAgICAgICAgY291bnRlcltibG9ja1NpemUgLSAxXSA9IChjb3VudGVyW2Jsb2NrU2l6ZSAtIDFdICsgMSkgfCAwXG5cblx0ICAgICAgICAgICAgLy8gRW5jcnlwdFxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJsb2NrU2l6ZTsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICB3b3Jkc1tvZmZzZXQgKyBpXSBePSBrZXlzdHJlYW1baV07XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgQ1RSLkRlY3J5cHRvciA9IEVuY3J5cHRvcjtcblxuXHQgICAgcmV0dXJuIENUUjtcblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5tb2RlLkNUUjtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9jaXBoZXItY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0LyoqXG5cdCAqIEVsZWN0cm9uaWMgQ29kZWJvb2sgYmxvY2sgbW9kZS5cblx0ICovXG5cdENyeXB0b0pTLm1vZGUuRUNCID0gKGZ1bmN0aW9uICgpIHtcblx0ICAgIHZhciBFQ0IgPSBDcnlwdG9KUy5saWIuQmxvY2tDaXBoZXJNb2RlLmV4dGVuZCgpO1xuXG5cdCAgICBFQ0IuRW5jcnlwdG9yID0gRUNCLmV4dGVuZCh7XG5cdCAgICAgICAgcHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAod29yZHMsIG9mZnNldCkge1xuXHQgICAgICAgICAgICB0aGlzLl9jaXBoZXIuZW5jcnlwdEJsb2NrKHdvcmRzLCBvZmZzZXQpO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICBFQ0IuRGVjcnlwdG9yID0gRUNCLmV4dGVuZCh7XG5cdCAgICAgICAgcHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAod29yZHMsIG9mZnNldCkge1xuXHQgICAgICAgICAgICB0aGlzLl9jaXBoZXIuZGVjcnlwdEJsb2NrKHdvcmRzLCBvZmZzZXQpO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICByZXR1cm4gRUNCO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLm1vZGUuRUNCO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NpcGhlci1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogT3V0cHV0IEZlZWRiYWNrIGJsb2NrIG1vZGUuXG5cdCAqL1xuXHRDcnlwdG9KUy5tb2RlLk9GQiA9IChmdW5jdGlvbiAoKSB7XG5cdCAgICB2YXIgT0ZCID0gQ3J5cHRvSlMubGliLkJsb2NrQ2lwaGVyTW9kZS5leHRlbmQoKTtcblxuXHQgICAgdmFyIEVuY3J5cHRvciA9IE9GQi5FbmNyeXB0b3IgPSBPRkIuZXh0ZW5kKHtcblx0ICAgICAgICBwcm9jZXNzQmxvY2s6IGZ1bmN0aW9uICh3b3Jkcywgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgY2lwaGVyID0gdGhpcy5fY2lwaGVyXG5cdCAgICAgICAgICAgIHZhciBibG9ja1NpemUgPSBjaXBoZXIuYmxvY2tTaXplO1xuXHQgICAgICAgICAgICB2YXIgaXYgPSB0aGlzLl9pdjtcblx0ICAgICAgICAgICAgdmFyIGtleXN0cmVhbSA9IHRoaXMuX2tleXN0cmVhbTtcblxuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSBrZXlzdHJlYW1cblx0ICAgICAgICAgICAgaWYgKGl2KSB7XG5cdCAgICAgICAgICAgICAgICBrZXlzdHJlYW0gPSB0aGlzLl9rZXlzdHJlYW0gPSBpdi5zbGljZSgwKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIElWIGZvciBzdWJzZXF1ZW50IGJsb2Nrc1xuXHQgICAgICAgICAgICAgICAgdGhpcy5faXYgPSB1bmRlZmluZWQ7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgY2lwaGVyLmVuY3J5cHRCbG9jayhrZXlzdHJlYW0sIDApO1xuXG5cdCAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBibG9ja1NpemU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbb2Zmc2V0ICsgaV0gXj0ga2V5c3RyZWFtW2ldO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIE9GQi5EZWNyeXB0b3IgPSBFbmNyeXB0b3I7XG5cblx0ICAgIHJldHVybiBPRkI7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMubW9kZS5PRkI7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdC8qKlxuXHQgKiBBTlNJIFguOTIzIHBhZGRpbmcgc3RyYXRlZ3kuXG5cdCAqL1xuXHRDcnlwdG9KUy5wYWQuQW5zaVg5MjMgPSB7XG5cdCAgICBwYWQ6IGZ1bmN0aW9uIChkYXRhLCBibG9ja1NpemUpIHtcblx0ICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICB2YXIgZGF0YVNpZ0J5dGVzID0gZGF0YS5zaWdCeXRlcztcblx0ICAgICAgICB2YXIgYmxvY2tTaXplQnl0ZXMgPSBibG9ja1NpemUgKiA0O1xuXG5cdCAgICAgICAgLy8gQ291bnQgcGFkZGluZyBieXRlc1xuXHQgICAgICAgIHZhciBuUGFkZGluZ0J5dGVzID0gYmxvY2tTaXplQnl0ZXMgLSBkYXRhU2lnQnl0ZXMgJSBibG9ja1NpemVCeXRlcztcblxuXHQgICAgICAgIC8vIENvbXB1dGUgbGFzdCBieXRlIHBvc2l0aW9uXG5cdCAgICAgICAgdmFyIGxhc3RCeXRlUG9zID0gZGF0YVNpZ0J5dGVzICsgblBhZGRpbmdCeXRlcyAtIDE7XG5cblx0ICAgICAgICAvLyBQYWRcblx0ICAgICAgICBkYXRhLmNsYW1wKCk7XG5cdCAgICAgICAgZGF0YS53b3Jkc1tsYXN0Qnl0ZVBvcyA+Pj4gMl0gfD0gblBhZGRpbmdCeXRlcyA8PCAoMjQgLSAobGFzdEJ5dGVQb3MgJSA0KSAqIDgpO1xuXHQgICAgICAgIGRhdGEuc2lnQnl0ZXMgKz0gblBhZGRpbmdCeXRlcztcblx0ICAgIH0sXG5cblx0ICAgIHVucGFkOiBmdW5jdGlvbiAoZGF0YSkge1xuXHQgICAgICAgIC8vIEdldCBudW1iZXIgb2YgcGFkZGluZyBieXRlcyBmcm9tIGxhc3QgYnl0ZVxuXHQgICAgICAgIHZhciBuUGFkZGluZ0J5dGVzID0gZGF0YS53b3Jkc1soZGF0YS5zaWdCeXRlcyAtIDEpID4+PiAyXSAmIDB4ZmY7XG5cblx0ICAgICAgICAvLyBSZW1vdmUgcGFkZGluZ1xuXHQgICAgICAgIGRhdGEuc2lnQnl0ZXMgLT0gblBhZGRpbmdCeXRlcztcblx0ICAgIH1cblx0fTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5wYWQuQW5zaXg5MjM7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdC8qKlxuXHQgKiBJU08gMTAxMjYgcGFkZGluZyBzdHJhdGVneS5cblx0ICovXG5cdENyeXB0b0pTLnBhZC5Jc28xMDEyNiA9IHtcblx0ICAgIHBhZDogZnVuY3Rpb24gKGRhdGEsIGJsb2NrU2l6ZSkge1xuXHQgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgdmFyIGJsb2NrU2l6ZUJ5dGVzID0gYmxvY2tTaXplICogNDtcblxuXHQgICAgICAgIC8vIENvdW50IHBhZGRpbmcgYnl0ZXNcblx0ICAgICAgICB2YXIgblBhZGRpbmdCeXRlcyA9IGJsb2NrU2l6ZUJ5dGVzIC0gZGF0YS5zaWdCeXRlcyAlIGJsb2NrU2l6ZUJ5dGVzO1xuXG5cdCAgICAgICAgLy8gUGFkXG5cdCAgICAgICAgZGF0YS5jb25jYXQoQ3J5cHRvSlMubGliLldvcmRBcnJheS5yYW5kb20oblBhZGRpbmdCeXRlcyAtIDEpKS5cblx0ICAgICAgICAgICAgIGNvbmNhdChDcnlwdG9KUy5saWIuV29yZEFycmF5LmNyZWF0ZShbblBhZGRpbmdCeXRlcyA8PCAyNF0sIDEpKTtcblx0ICAgIH0sXG5cblx0ICAgIHVucGFkOiBmdW5jdGlvbiAoZGF0YSkge1xuXHQgICAgICAgIC8vIEdldCBudW1iZXIgb2YgcGFkZGluZyBieXRlcyBmcm9tIGxhc3QgYnl0ZVxuXHQgICAgICAgIHZhciBuUGFkZGluZ0J5dGVzID0gZGF0YS53b3Jkc1soZGF0YS5zaWdCeXRlcyAtIDEpID4+PiAyXSAmIDB4ZmY7XG5cblx0ICAgICAgICAvLyBSZW1vdmUgcGFkZGluZ1xuXHQgICAgICAgIGRhdGEuc2lnQnl0ZXMgLT0gblBhZGRpbmdCeXRlcztcblx0ICAgIH1cblx0fTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5wYWQuSXNvMTAxMjY7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdC8qKlxuXHQgKiBJU08vSUVDIDk3OTctMSBQYWRkaW5nIE1ldGhvZCAyLlxuXHQgKi9cblx0Q3J5cHRvSlMucGFkLklzbzk3OTcxID0ge1xuXHQgICAgcGFkOiBmdW5jdGlvbiAoZGF0YSwgYmxvY2tTaXplKSB7XG5cdCAgICAgICAgLy8gQWRkIDB4ODAgYnl0ZVxuXHQgICAgICAgIGRhdGEuY29uY2F0KENyeXB0b0pTLmxpYi5Xb3JkQXJyYXkuY3JlYXRlKFsweDgwMDAwMDAwXSwgMSkpO1xuXG5cdCAgICAgICAgLy8gWmVybyBwYWQgdGhlIHJlc3Rcblx0ICAgICAgICBDcnlwdG9KUy5wYWQuWmVyb1BhZGRpbmcucGFkKGRhdGEsIGJsb2NrU2l6ZSk7XG5cdCAgICB9LFxuXG5cdCAgICB1bnBhZDogZnVuY3Rpb24gKGRhdGEpIHtcblx0ICAgICAgICAvLyBSZW1vdmUgemVybyBwYWRkaW5nXG5cdCAgICAgICAgQ3J5cHRvSlMucGFkLlplcm9QYWRkaW5nLnVucGFkKGRhdGEpO1xuXG5cdCAgICAgICAgLy8gUmVtb3ZlIG9uZSBtb3JlIGJ5dGUgLS0gdGhlIDB4ODAgYnl0ZVxuXHQgICAgICAgIGRhdGEuc2lnQnl0ZXMtLTtcblx0ICAgIH1cblx0fTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5wYWQuSXNvOTc5NzE7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdC8qKlxuXHQgKiBBIG5vb3AgcGFkZGluZyBzdHJhdGVneS5cblx0ICovXG5cdENyeXB0b0pTLnBhZC5Ob1BhZGRpbmcgPSB7XG5cdCAgICBwYWQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgIH0sXG5cblx0ICAgIHVucGFkOiBmdW5jdGlvbiAoKSB7XG5cdCAgICB9XG5cdH07XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMucGFkLk5vUGFkZGluZztcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9jaXBoZXItY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0LyoqXG5cdCAqIFplcm8gcGFkZGluZyBzdHJhdGVneS5cblx0ICovXG5cdENyeXB0b0pTLnBhZC5aZXJvUGFkZGluZyA9IHtcblx0ICAgIHBhZDogZnVuY3Rpb24gKGRhdGEsIGJsb2NrU2l6ZSkge1xuXHQgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgdmFyIGJsb2NrU2l6ZUJ5dGVzID0gYmxvY2tTaXplICogNDtcblxuXHQgICAgICAgIC8vIFBhZFxuXHQgICAgICAgIGRhdGEuY2xhbXAoKTtcblx0ICAgICAgICBkYXRhLnNpZ0J5dGVzICs9IGJsb2NrU2l6ZUJ5dGVzIC0gKChkYXRhLnNpZ0J5dGVzICUgYmxvY2tTaXplQnl0ZXMpIHx8IGJsb2NrU2l6ZUJ5dGVzKTtcblx0ICAgIH0sXG5cblx0ICAgIHVucGFkOiBmdW5jdGlvbiAoZGF0YSkge1xuXHQgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgdmFyIGRhdGFXb3JkcyA9IGRhdGEud29yZHM7XG5cblx0ICAgICAgICAvLyBVbnBhZFxuXHQgICAgICAgIHZhciBpID0gZGF0YS5zaWdCeXRlcyAtIDE7XG5cdCAgICAgICAgd2hpbGUgKCEoKGRhdGFXb3Jkc1tpID4+PiAyXSA+Pj4gKDI0IC0gKGkgJSA0KSAqIDgpKSAmIDB4ZmYpKSB7XG5cdCAgICAgICAgICAgIGktLTtcblx0ICAgICAgICB9XG5cdCAgICAgICAgZGF0YS5zaWdCeXRlcyA9IGkgKyAxO1xuXHQgICAgfVxuXHR9O1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLnBhZC5aZXJvUGFkZGluZztcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9zaGExXCIpLCByZXF1aXJlKFwiLi9obWFjXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL3NoYTFcIiwgXCIuL2htYWNcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBCYXNlID0gQ19saWIuQmFzZTtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXHQgICAgdmFyIFNIQTEgPSBDX2FsZ28uU0hBMTtcblx0ICAgIHZhciBITUFDID0gQ19hbGdvLkhNQUM7XG5cblx0ICAgIC8qKlxuXHQgICAgICogUGFzc3dvcmQtQmFzZWQgS2V5IERlcml2YXRpb24gRnVuY3Rpb24gMiBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBQQktERjIgPSBDX2FsZ28uUEJLREYyID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmZpZ3VyYXRpb24gb3B0aW9ucy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBrZXlTaXplIFRoZSBrZXkgc2l6ZSBpbiB3b3JkcyB0byBnZW5lcmF0ZS4gRGVmYXVsdDogNCAoMTI4IGJpdHMpXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtIYXNoZXJ9IGhhc2hlciBUaGUgaGFzaGVyIHRvIHVzZS4gRGVmYXVsdDogU0hBMVxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBpdGVyYXRpb25zIFRoZSBudW1iZXIgb2YgaXRlcmF0aW9ucyB0byBwZXJmb3JtLiBEZWZhdWx0OiAxXG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2ZnOiBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgICAgIGtleVNpemU6IDEyOC8zMixcblx0ICAgICAgICAgICAgaGFzaGVyOiBTSEExLFxuXHQgICAgICAgICAgICBpdGVyYXRpb25zOiAxXG5cdCAgICAgICAgfSksXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQga2V5IGRlcml2YXRpb24gZnVuY3Rpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoZSBkZXJpdmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIga2RmID0gQ3J5cHRvSlMuYWxnby5QQktERjIuY3JlYXRlKCk7XG5cdCAgICAgICAgICogICAgIHZhciBrZGYgPSBDcnlwdG9KUy5hbGdvLlBCS0RGMi5jcmVhdGUoeyBrZXlTaXplOiA4IH0pO1xuXHQgICAgICAgICAqICAgICB2YXIga2RmID0gQ3J5cHRvSlMuYWxnby5QQktERjIuY3JlYXRlKHsga2V5U2l6ZTogOCwgaXRlcmF0aW9uczogMTAwMCB9KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoY2ZnKSB7XG5cdCAgICAgICAgICAgIHRoaXMuY2ZnID0gdGhpcy5jZmcuZXh0ZW5kKGNmZyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbXB1dGVzIHRoZSBQYXNzd29yZC1CYXNlZCBLZXkgRGVyaXZhdGlvbiBGdW5jdGlvbiAyLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBzYWx0IEEgc2FsdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGRlcml2ZWQga2V5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIga2V5ID0ga2RmLmNvbXB1dGUocGFzc3dvcmQsIHNhbHQpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNvbXB1dGU6IGZ1bmN0aW9uIChwYXNzd29yZCwgc2FsdCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgY2ZnID0gdGhpcy5jZmc7XG5cblx0ICAgICAgICAgICAgLy8gSW5pdCBITUFDXG5cdCAgICAgICAgICAgIHZhciBobWFjID0gSE1BQy5jcmVhdGUoY2ZnLmhhc2hlciwgcGFzc3dvcmQpO1xuXG5cdCAgICAgICAgICAgIC8vIEluaXRpYWwgdmFsdWVzXG5cdCAgICAgICAgICAgIHZhciBkZXJpdmVkS2V5ID0gV29yZEFycmF5LmNyZWF0ZSgpO1xuXHQgICAgICAgICAgICB2YXIgYmxvY2tJbmRleCA9IFdvcmRBcnJheS5jcmVhdGUoWzB4MDAwMDAwMDFdKTtcblxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGRlcml2ZWRLZXlXb3JkcyA9IGRlcml2ZWRLZXkud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBibG9ja0luZGV4V29yZHMgPSBibG9ja0luZGV4LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIga2V5U2l6ZSA9IGNmZy5rZXlTaXplO1xuXHQgICAgICAgICAgICB2YXIgaXRlcmF0aW9ucyA9IGNmZy5pdGVyYXRpb25zO1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGtleVxuXHQgICAgICAgICAgICB3aGlsZSAoZGVyaXZlZEtleVdvcmRzLmxlbmd0aCA8IGtleVNpemUpIHtcblx0ICAgICAgICAgICAgICAgIHZhciBibG9jayA9IGhtYWMudXBkYXRlKHNhbHQpLmZpbmFsaXplKGJsb2NrSW5kZXgpO1xuXHQgICAgICAgICAgICAgICAgaG1hYy5yZXNldCgpO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgIHZhciBibG9ja1dvcmRzID0gYmxvY2sud29yZHM7XG5cdCAgICAgICAgICAgICAgICB2YXIgYmxvY2tXb3Jkc0xlbmd0aCA9IGJsb2NrV29yZHMubGVuZ3RoO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBJdGVyYXRpb25zXG5cdCAgICAgICAgICAgICAgICB2YXIgaW50ZXJtZWRpYXRlID0gYmxvY2s7XG5cdCAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMTsgaSA8IGl0ZXJhdGlvbnM7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgICAgIGludGVybWVkaWF0ZSA9IGhtYWMuZmluYWxpemUoaW50ZXJtZWRpYXRlKTtcblx0ICAgICAgICAgICAgICAgICAgICBobWFjLnJlc2V0KCk7XG5cblx0ICAgICAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICAgICAgICAgIHZhciBpbnRlcm1lZGlhdGVXb3JkcyA9IGludGVybWVkaWF0ZS53b3JkcztcblxuXHQgICAgICAgICAgICAgICAgICAgIC8vIFhPUiBpbnRlcm1lZGlhdGUgd2l0aCBibG9ja1xuXHQgICAgICAgICAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgYmxvY2tXb3Jkc0xlbmd0aDsgaisrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIGJsb2NrV29yZHNbal0gXj0gaW50ZXJtZWRpYXRlV29yZHNbal07XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICBkZXJpdmVkS2V5LmNvbmNhdChibG9jayk7XG5cdCAgICAgICAgICAgICAgICBibG9ja0luZGV4V29yZHNbMF0rKztcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICBkZXJpdmVkS2V5LnNpZ0J5dGVzID0ga2V5U2l6ZSAqIDQ7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGRlcml2ZWRLZXk7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogQ29tcHV0ZXMgdGhlIFBhc3N3b3JkLUJhc2VkIEtleSBEZXJpdmF0aW9uIEZ1bmN0aW9uIDIuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQuXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IHNhbHQgQSBzYWx0LlxuXHQgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIGNvbXB1dGF0aW9uLlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGRlcml2ZWQga2V5LlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIga2V5ID0gQ3J5cHRvSlMuUEJLREYyKHBhc3N3b3JkLCBzYWx0KTtcblx0ICAgICAqICAgICB2YXIga2V5ID0gQ3J5cHRvSlMuUEJLREYyKHBhc3N3b3JkLCBzYWx0LCB7IGtleVNpemU6IDggfSk7XG5cdCAgICAgKiAgICAgdmFyIGtleSA9IENyeXB0b0pTLlBCS0RGMihwYXNzd29yZCwgc2FsdCwgeyBrZXlTaXplOiA4LCBpdGVyYXRpb25zOiAxMDAwIH0pO1xuXHQgICAgICovXG5cdCAgICBDLlBCS0RGMiA9IGZ1bmN0aW9uIChwYXNzd29yZCwgc2FsdCwgY2ZnKSB7XG5cdCAgICAgICAgcmV0dXJuIFBCS0RGMi5jcmVhdGUoY2ZnKS5jb21wdXRlKHBhc3N3b3JkLCBzYWx0KTtcblx0ICAgIH07XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuUEJLREYyO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2VuYy1iYXNlNjRcIiksIHJlcXVpcmUoXCIuL21kNVwiKSwgcmVxdWlyZShcIi4vZXZwa2RmXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9lbmMtYmFzZTY0XCIsIFwiLi9tZDVcIiwgXCIuL2V2cGtkZlwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBTdHJlYW1DaXBoZXIgPSBDX2xpYi5TdHJlYW1DaXBoZXI7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICAvLyBSZXVzYWJsZSBvYmplY3RzXG5cdCAgICB2YXIgUyAgPSBbXTtcblx0ICAgIHZhciBDXyA9IFtdO1xuXHQgICAgdmFyIEcgID0gW107XG5cblx0ICAgIC8qKlxuXHQgICAgICogUmFiYml0IHN0cmVhbSBjaXBoZXIgYWxnb3JpdGhtLlxuXHQgICAgICpcblx0ICAgICAqIFRoaXMgaXMgYSBsZWdhY3kgdmVyc2lvbiB0aGF0IG5lZ2xlY3RlZCB0byBjb252ZXJ0IHRoZSBrZXkgdG8gbGl0dGxlLWVuZGlhbi5cblx0ICAgICAqIFRoaXMgZXJyb3IgZG9lc24ndCBhZmZlY3QgdGhlIGNpcGhlcidzIHNlY3VyaXR5LFxuXHQgICAgICogYnV0IGl0IGRvZXMgYWZmZWN0IGl0cyBjb21wYXRpYmlsaXR5IHdpdGggb3RoZXIgaW1wbGVtZW50YXRpb25zLlxuXHQgICAgICovXG5cdCAgICB2YXIgUmFiYml0TGVnYWN5ID0gQ19hbGdvLlJhYmJpdExlZ2FjeSA9IFN0cmVhbUNpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgSyA9IHRoaXMuX2tleS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIGl2ID0gdGhpcy5jZmcuaXY7XG5cblx0ICAgICAgICAgICAgLy8gR2VuZXJhdGUgaW5pdGlhbCBzdGF0ZSB2YWx1ZXNcblx0ICAgICAgICAgICAgdmFyIFggPSB0aGlzLl9YID0gW1xuXHQgICAgICAgICAgICAgICAgS1swXSwgKEtbM10gPDwgMTYpIHwgKEtbMl0gPj4+IDE2KSxcblx0ICAgICAgICAgICAgICAgIEtbMV0sIChLWzBdIDw8IDE2KSB8IChLWzNdID4+PiAxNiksXG5cdCAgICAgICAgICAgICAgICBLWzJdLCAoS1sxXSA8PCAxNikgfCAoS1swXSA+Pj4gMTYpLFxuXHQgICAgICAgICAgICAgICAgS1szXSwgKEtbMl0gPDwgMTYpIHwgKEtbMV0gPj4+IDE2KVxuXHQgICAgICAgICAgICBdO1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGluaXRpYWwgY291bnRlciB2YWx1ZXNcblx0ICAgICAgICAgICAgdmFyIEMgPSB0aGlzLl9DID0gW1xuXHQgICAgICAgICAgICAgICAgKEtbMl0gPDwgMTYpIHwgKEtbMl0gPj4+IDE2KSwgKEtbMF0gJiAweGZmZmYwMDAwKSB8IChLWzFdICYgMHgwMDAwZmZmZiksXG5cdCAgICAgICAgICAgICAgICAoS1szXSA8PCAxNikgfCAoS1szXSA+Pj4gMTYpLCAoS1sxXSAmIDB4ZmZmZjAwMDApIHwgKEtbMl0gJiAweDAwMDBmZmZmKSxcblx0ICAgICAgICAgICAgICAgIChLWzBdIDw8IDE2KSB8IChLWzBdID4+PiAxNiksIChLWzJdICYgMHhmZmZmMDAwMCkgfCAoS1szXSAmIDB4MDAwMGZmZmYpLFxuXHQgICAgICAgICAgICAgICAgKEtbMV0gPDwgMTYpIHwgKEtbMV0gPj4+IDE2KSwgKEtbM10gJiAweGZmZmYwMDAwKSB8IChLWzBdICYgMHgwMDAwZmZmZilcblx0ICAgICAgICAgICAgXTtcblxuXHQgICAgICAgICAgICAvLyBDYXJyeSBiaXRcblx0ICAgICAgICAgICAgdGhpcy5fYiA9IDA7XG5cblx0ICAgICAgICAgICAgLy8gSXRlcmF0ZSB0aGUgc3lzdGVtIGZvdXIgdGltZXNcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIG5leHRTdGF0ZS5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gTW9kaWZ5IHRoZSBjb3VudGVyc1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDg7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgQ1tpXSBePSBYWyhpICsgNCkgJiA3XTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIElWIHNldHVwXG5cdCAgICAgICAgICAgIGlmIChpdikge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgICAgICB2YXIgSVYgPSBpdi53b3Jkcztcblx0ICAgICAgICAgICAgICAgIHZhciBJVl8wID0gSVZbMF07XG5cdCAgICAgICAgICAgICAgICB2YXIgSVZfMSA9IElWWzFdO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBHZW5lcmF0ZSBmb3VyIHN1YnZlY3RvcnNcblx0ICAgICAgICAgICAgICAgIHZhciBpMCA9ICgoKElWXzAgPDwgOCkgfCAoSVZfMCA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHwgKCgoSVZfMCA8PCAyNCkgfCAoSVZfMCA+Pj4gOCkpICYgMHhmZjAwZmYwMCk7XG5cdCAgICAgICAgICAgICAgICB2YXIgaTIgPSAoKChJVl8xIDw8IDgpIHwgKElWXzEgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8ICgoKElWXzEgPDwgMjQpIHwgKElWXzEgPj4+IDgpKSAmIDB4ZmYwMGZmMDApO1xuXHQgICAgICAgICAgICAgICAgdmFyIGkxID0gKGkwID4+PiAxNikgfCAoaTIgJiAweGZmZmYwMDAwKTtcblx0ICAgICAgICAgICAgICAgIHZhciBpMyA9IChpMiA8PCAxNikgIHwgKGkwICYgMHgwMDAwZmZmZik7XG5cblx0ICAgICAgICAgICAgICAgIC8vIE1vZGlmeSBjb3VudGVyIHZhbHVlc1xuXHQgICAgICAgICAgICAgICAgQ1swXSBePSBpMDtcblx0ICAgICAgICAgICAgICAgIENbMV0gXj0gaTE7XG5cdCAgICAgICAgICAgICAgICBDWzJdIF49IGkyO1xuXHQgICAgICAgICAgICAgICAgQ1szXSBePSBpMztcblx0ICAgICAgICAgICAgICAgIENbNF0gXj0gaTA7XG5cdCAgICAgICAgICAgICAgICBDWzVdIF49IGkxO1xuXHQgICAgICAgICAgICAgICAgQ1s2XSBePSBpMjtcblx0ICAgICAgICAgICAgICAgIENbN10gXj0gaTM7XG5cblx0ICAgICAgICAgICAgICAgIC8vIEl0ZXJhdGUgdGhlIHN5c3RlbSBmb3VyIHRpbWVzXG5cdCAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDQ7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgICAgIG5leHRTdGF0ZS5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgWCA9IHRoaXMuX1g7XG5cblx0ICAgICAgICAgICAgLy8gSXRlcmF0ZSB0aGUgc3lzdGVtXG5cdCAgICAgICAgICAgIG5leHRTdGF0ZS5jYWxsKHRoaXMpO1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGZvdXIga2V5c3RyZWFtIHdvcmRzXG5cdCAgICAgICAgICAgIFNbMF0gPSBYWzBdIF4gKFhbNV0gPj4+IDE2KSBeIChYWzNdIDw8IDE2KTtcblx0ICAgICAgICAgICAgU1sxXSA9IFhbMl0gXiAoWFs3XSA+Pj4gMTYpIF4gKFhbNV0gPDwgMTYpO1xuXHQgICAgICAgICAgICBTWzJdID0gWFs0XSBeIChYWzFdID4+PiAxNikgXiAoWFs3XSA8PCAxNik7XG5cdCAgICAgICAgICAgIFNbM10gPSBYWzZdIF4gKFhbM10gPj4+IDE2KSBeIChYWzFdIDw8IDE2KTtcblxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDQ7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU3dhcCBlbmRpYW5cblx0ICAgICAgICAgICAgICAgIFNbaV0gPSAoKChTW2ldIDw8IDgpICB8IChTW2ldID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgICAgICAgICgoKFNbaV0gPDwgMjQpIHwgKFNbaV0gPj4+IDgpKSAgJiAweGZmMDBmZjAwKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gRW5jcnlwdFxuXHQgICAgICAgICAgICAgICAgTVtvZmZzZXQgKyBpXSBePSBTW2ldO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGJsb2NrU2l6ZTogMTI4LzMyLFxuXG5cdCAgICAgICAgaXZTaXplOiA2NC8zMlxuXHQgICAgfSk7XG5cblx0ICAgIGZ1bmN0aW9uIG5leHRTdGF0ZSgpIHtcblx0ICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICB2YXIgWCA9IHRoaXMuX1g7XG5cdCAgICAgICAgdmFyIEMgPSB0aGlzLl9DO1xuXG5cdCAgICAgICAgLy8gU2F2ZSBvbGQgY291bnRlciB2YWx1ZXNcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDg7IGkrKykge1xuXHQgICAgICAgICAgICBDX1tpXSA9IENbaV07XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gQ2FsY3VsYXRlIG5ldyBjb3VudGVyIHZhbHVlc1xuXHQgICAgICAgIENbMF0gPSAoQ1swXSArIDB4NGQzNGQzNGQgKyB0aGlzLl9iKSB8IDA7XG5cdCAgICAgICAgQ1sxXSA9IChDWzFdICsgMHhkMzRkMzRkMyArICgoQ1swXSA+Pj4gMCkgPCAoQ19bMF0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1syXSA9IChDWzJdICsgMHgzNGQzNGQzNCArICgoQ1sxXSA+Pj4gMCkgPCAoQ19bMV0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1szXSA9IChDWzNdICsgMHg0ZDM0ZDM0ZCArICgoQ1syXSA+Pj4gMCkgPCAoQ19bMl0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1s0XSA9IChDWzRdICsgMHhkMzRkMzRkMyArICgoQ1szXSA+Pj4gMCkgPCAoQ19bM10gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1s1XSA9IChDWzVdICsgMHgzNGQzNGQzNCArICgoQ1s0XSA+Pj4gMCkgPCAoQ19bNF0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1s2XSA9IChDWzZdICsgMHg0ZDM0ZDM0ZCArICgoQ1s1XSA+Pj4gMCkgPCAoQ19bNV0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1s3XSA9IChDWzddICsgMHhkMzRkMzRkMyArICgoQ1s2XSA+Pj4gMCkgPCAoQ19bNl0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgdGhpcy5fYiA9IChDWzddID4+PiAwKSA8IChDX1s3XSA+Pj4gMCkgPyAxIDogMDtcblxuXHQgICAgICAgIC8vIENhbGN1bGF0ZSB0aGUgZy12YWx1ZXNcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDg7IGkrKykge1xuXHQgICAgICAgICAgICB2YXIgZ3ggPSBYW2ldICsgQ1tpXTtcblxuXHQgICAgICAgICAgICAvLyBDb25zdHJ1Y3QgaGlnaCBhbmQgbG93IGFyZ3VtZW50IGZvciBzcXVhcmluZ1xuXHQgICAgICAgICAgICB2YXIgZ2EgPSBneCAmIDB4ZmZmZjtcblx0ICAgICAgICAgICAgdmFyIGdiID0gZ3ggPj4+IDE2O1xuXG5cdCAgICAgICAgICAgIC8vIENhbGN1bGF0ZSBoaWdoIGFuZCBsb3cgcmVzdWx0IG9mIHNxdWFyaW5nXG5cdCAgICAgICAgICAgIHZhciBnaCA9ICgoKChnYSAqIGdhKSA+Pj4gMTcpICsgZ2EgKiBnYikgPj4+IDE1KSArIGdiICogZ2I7XG5cdCAgICAgICAgICAgIHZhciBnbCA9ICgoKGd4ICYgMHhmZmZmMDAwMCkgKiBneCkgfCAwKSArICgoKGd4ICYgMHgwMDAwZmZmZikgKiBneCkgfCAwKTtcblxuXHQgICAgICAgICAgICAvLyBIaWdoIFhPUiBsb3dcblx0ICAgICAgICAgICAgR1tpXSA9IGdoIF4gZ2w7XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gQ2FsY3VsYXRlIG5ldyBzdGF0ZSB2YWx1ZXNcblx0ICAgICAgICBYWzBdID0gKEdbMF0gKyAoKEdbN10gPDwgMTYpIHwgKEdbN10gPj4+IDE2KSkgKyAoKEdbNl0gPDwgMTYpIHwgKEdbNl0gPj4+IDE2KSkpIHwgMDtcblx0ICAgICAgICBYWzFdID0gKEdbMV0gKyAoKEdbMF0gPDwgOCkgIHwgKEdbMF0gPj4+IDI0KSkgKyBHWzddKSB8IDA7XG5cdCAgICAgICAgWFsyXSA9IChHWzJdICsgKChHWzFdIDw8IDE2KSB8IChHWzFdID4+PiAxNikpICsgKChHWzBdIDw8IDE2KSB8IChHWzBdID4+PiAxNikpKSB8IDA7XG5cdCAgICAgICAgWFszXSA9IChHWzNdICsgKChHWzJdIDw8IDgpICB8IChHWzJdID4+PiAyNCkpICsgR1sxXSkgfCAwO1xuXHQgICAgICAgIFhbNF0gPSAoR1s0XSArICgoR1szXSA8PCAxNikgfCAoR1szXSA+Pj4gMTYpKSArICgoR1syXSA8PCAxNikgfCAoR1syXSA+Pj4gMTYpKSkgfCAwO1xuXHQgICAgICAgIFhbNV0gPSAoR1s1XSArICgoR1s0XSA8PCA4KSAgfCAoR1s0XSA+Pj4gMjQpKSArIEdbM10pIHwgMDtcblx0ICAgICAgICBYWzZdID0gKEdbNl0gKyAoKEdbNV0gPDwgMTYpIHwgKEdbNV0gPj4+IDE2KSkgKyAoKEdbNF0gPDwgMTYpIHwgKEdbNF0gPj4+IDE2KSkpIHwgMDtcblx0ICAgICAgICBYWzddID0gKEdbN10gKyAoKEdbNl0gPDwgOCkgIHwgKEdbNl0gPj4+IDI0KSkgKyBHWzVdKSB8IDA7XG5cdCAgICB9XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb25zIHRvIHRoZSBjaXBoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0ID0gQ3J5cHRvSlMuUmFiYml0TGVnYWN5LmVuY3J5cHQobWVzc2FnZSwga2V5LCBjZmcpO1xuXHQgICAgICogICAgIHZhciBwbGFpbnRleHQgID0gQ3J5cHRvSlMuUmFiYml0TGVnYWN5LmRlY3J5cHQoY2lwaGVydGV4dCwga2V5LCBjZmcpO1xuXHQgICAgICovXG5cdCAgICBDLlJhYmJpdExlZ2FjeSA9IFN0cmVhbUNpcGhlci5fY3JlYXRlSGVscGVyKFJhYmJpdExlZ2FjeSk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuUmFiYml0TGVnYWN5O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2VuYy1iYXNlNjRcIiksIHJlcXVpcmUoXCIuL21kNVwiKSwgcmVxdWlyZShcIi4vZXZwa2RmXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9lbmMtYmFzZTY0XCIsIFwiLi9tZDVcIiwgXCIuL2V2cGtkZlwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBTdHJlYW1DaXBoZXIgPSBDX2xpYi5TdHJlYW1DaXBoZXI7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICAvLyBSZXVzYWJsZSBvYmplY3RzXG5cdCAgICB2YXIgUyAgPSBbXTtcblx0ICAgIHZhciBDXyA9IFtdO1xuXHQgICAgdmFyIEcgID0gW107XG5cblx0ICAgIC8qKlxuXHQgICAgICogUmFiYml0IHN0cmVhbSBjaXBoZXIgYWxnb3JpdGhtXG5cdCAgICAgKi9cblx0ICAgIHZhciBSYWJiaXQgPSBDX2FsZ28uUmFiYml0ID0gU3RyZWFtQ2lwaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgX2RvUmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBLID0gdGhpcy5fa2V5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgaXYgPSB0aGlzLmNmZy5pdjtcblxuXHQgICAgICAgICAgICAvLyBTd2FwIGVuZGlhblxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDQ7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgS1tpXSA9ICgoKEtbaV0gPDwgOCkgIHwgKEtbaV0gPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8XG5cdCAgICAgICAgICAgICAgICAgICAgICAgKCgoS1tpXSA8PCAyNCkgfCAoS1tpXSA+Pj4gOCkpICAmIDB4ZmYwMGZmMDApO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gR2VuZXJhdGUgaW5pdGlhbCBzdGF0ZSB2YWx1ZXNcblx0ICAgICAgICAgICAgdmFyIFggPSB0aGlzLl9YID0gW1xuXHQgICAgICAgICAgICAgICAgS1swXSwgKEtbM10gPDwgMTYpIHwgKEtbMl0gPj4+IDE2KSxcblx0ICAgICAgICAgICAgICAgIEtbMV0sIChLWzBdIDw8IDE2KSB8IChLWzNdID4+PiAxNiksXG5cdCAgICAgICAgICAgICAgICBLWzJdLCAoS1sxXSA8PCAxNikgfCAoS1swXSA+Pj4gMTYpLFxuXHQgICAgICAgICAgICAgICAgS1szXSwgKEtbMl0gPDwgMTYpIHwgKEtbMV0gPj4+IDE2KVxuXHQgICAgICAgICAgICBdO1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGluaXRpYWwgY291bnRlciB2YWx1ZXNcblx0ICAgICAgICAgICAgdmFyIEMgPSB0aGlzLl9DID0gW1xuXHQgICAgICAgICAgICAgICAgKEtbMl0gPDwgMTYpIHwgKEtbMl0gPj4+IDE2KSwgKEtbMF0gJiAweGZmZmYwMDAwKSB8IChLWzFdICYgMHgwMDAwZmZmZiksXG5cdCAgICAgICAgICAgICAgICAoS1szXSA8PCAxNikgfCAoS1szXSA+Pj4gMTYpLCAoS1sxXSAmIDB4ZmZmZjAwMDApIHwgKEtbMl0gJiAweDAwMDBmZmZmKSxcblx0ICAgICAgICAgICAgICAgIChLWzBdIDw8IDE2KSB8IChLWzBdID4+PiAxNiksIChLWzJdICYgMHhmZmZmMDAwMCkgfCAoS1szXSAmIDB4MDAwMGZmZmYpLFxuXHQgICAgICAgICAgICAgICAgKEtbMV0gPDwgMTYpIHwgKEtbMV0gPj4+IDE2KSwgKEtbM10gJiAweGZmZmYwMDAwKSB8IChLWzBdICYgMHgwMDAwZmZmZilcblx0ICAgICAgICAgICAgXTtcblxuXHQgICAgICAgICAgICAvLyBDYXJyeSBiaXRcblx0ICAgICAgICAgICAgdGhpcy5fYiA9IDA7XG5cblx0ICAgICAgICAgICAgLy8gSXRlcmF0ZSB0aGUgc3lzdGVtIGZvdXIgdGltZXNcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIG5leHRTdGF0ZS5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gTW9kaWZ5IHRoZSBjb3VudGVyc1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDg7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgQ1tpXSBePSBYWyhpICsgNCkgJiA3XTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIElWIHNldHVwXG5cdCAgICAgICAgICAgIGlmIChpdikge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgICAgICB2YXIgSVYgPSBpdi53b3Jkcztcblx0ICAgICAgICAgICAgICAgIHZhciBJVl8wID0gSVZbMF07XG5cdCAgICAgICAgICAgICAgICB2YXIgSVZfMSA9IElWWzFdO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBHZW5lcmF0ZSBmb3VyIHN1YnZlY3RvcnNcblx0ICAgICAgICAgICAgICAgIHZhciBpMCA9ICgoKElWXzAgPDwgOCkgfCAoSVZfMCA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHwgKCgoSVZfMCA8PCAyNCkgfCAoSVZfMCA+Pj4gOCkpICYgMHhmZjAwZmYwMCk7XG5cdCAgICAgICAgICAgICAgICB2YXIgaTIgPSAoKChJVl8xIDw8IDgpIHwgKElWXzEgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8ICgoKElWXzEgPDwgMjQpIHwgKElWXzEgPj4+IDgpKSAmIDB4ZmYwMGZmMDApO1xuXHQgICAgICAgICAgICAgICAgdmFyIGkxID0gKGkwID4+PiAxNikgfCAoaTIgJiAweGZmZmYwMDAwKTtcblx0ICAgICAgICAgICAgICAgIHZhciBpMyA9IChpMiA8PCAxNikgIHwgKGkwICYgMHgwMDAwZmZmZik7XG5cblx0ICAgICAgICAgICAgICAgIC8vIE1vZGlmeSBjb3VudGVyIHZhbHVlc1xuXHQgICAgICAgICAgICAgICAgQ1swXSBePSBpMDtcblx0ICAgICAgICAgICAgICAgIENbMV0gXj0gaTE7XG5cdCAgICAgICAgICAgICAgICBDWzJdIF49IGkyO1xuXHQgICAgICAgICAgICAgICAgQ1szXSBePSBpMztcblx0ICAgICAgICAgICAgICAgIENbNF0gXj0gaTA7XG5cdCAgICAgICAgICAgICAgICBDWzVdIF49IGkxO1xuXHQgICAgICAgICAgICAgICAgQ1s2XSBePSBpMjtcblx0ICAgICAgICAgICAgICAgIENbN10gXj0gaTM7XG5cblx0ICAgICAgICAgICAgICAgIC8vIEl0ZXJhdGUgdGhlIHN5c3RlbSBmb3VyIHRpbWVzXG5cdCAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDQ7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgICAgIG5leHRTdGF0ZS5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgWCA9IHRoaXMuX1g7XG5cblx0ICAgICAgICAgICAgLy8gSXRlcmF0ZSB0aGUgc3lzdGVtXG5cdCAgICAgICAgICAgIG5leHRTdGF0ZS5jYWxsKHRoaXMpO1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGZvdXIga2V5c3RyZWFtIHdvcmRzXG5cdCAgICAgICAgICAgIFNbMF0gPSBYWzBdIF4gKFhbNV0gPj4+IDE2KSBeIChYWzNdIDw8IDE2KTtcblx0ICAgICAgICAgICAgU1sxXSA9IFhbMl0gXiAoWFs3XSA+Pj4gMTYpIF4gKFhbNV0gPDwgMTYpO1xuXHQgICAgICAgICAgICBTWzJdID0gWFs0XSBeIChYWzFdID4+PiAxNikgXiAoWFs3XSA8PCAxNik7XG5cdCAgICAgICAgICAgIFNbM10gPSBYWzZdIF4gKFhbM10gPj4+IDE2KSBeIChYWzFdIDw8IDE2KTtcblxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDQ7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU3dhcCBlbmRpYW5cblx0ICAgICAgICAgICAgICAgIFNbaV0gPSAoKChTW2ldIDw8IDgpICB8IChTW2ldID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgICAgICAgICgoKFNbaV0gPDwgMjQpIHwgKFNbaV0gPj4+IDgpKSAgJiAweGZmMDBmZjAwKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gRW5jcnlwdFxuXHQgICAgICAgICAgICAgICAgTVtvZmZzZXQgKyBpXSBePSBTW2ldO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGJsb2NrU2l6ZTogMTI4LzMyLFxuXG5cdCAgICAgICAgaXZTaXplOiA2NC8zMlxuXHQgICAgfSk7XG5cblx0ICAgIGZ1bmN0aW9uIG5leHRTdGF0ZSgpIHtcblx0ICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICB2YXIgWCA9IHRoaXMuX1g7XG5cdCAgICAgICAgdmFyIEMgPSB0aGlzLl9DO1xuXG5cdCAgICAgICAgLy8gU2F2ZSBvbGQgY291bnRlciB2YWx1ZXNcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDg7IGkrKykge1xuXHQgICAgICAgICAgICBDX1tpXSA9IENbaV07XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gQ2FsY3VsYXRlIG5ldyBjb3VudGVyIHZhbHVlc1xuXHQgICAgICAgIENbMF0gPSAoQ1swXSArIDB4NGQzNGQzNGQgKyB0aGlzLl9iKSB8IDA7XG5cdCAgICAgICAgQ1sxXSA9IChDWzFdICsgMHhkMzRkMzRkMyArICgoQ1swXSA+Pj4gMCkgPCAoQ19bMF0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1syXSA9IChDWzJdICsgMHgzNGQzNGQzNCArICgoQ1sxXSA+Pj4gMCkgPCAoQ19bMV0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1szXSA9IChDWzNdICsgMHg0ZDM0ZDM0ZCArICgoQ1syXSA+Pj4gMCkgPCAoQ19bMl0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1s0XSA9IChDWzRdICsgMHhkMzRkMzRkMyArICgoQ1szXSA+Pj4gMCkgPCAoQ19bM10gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1s1XSA9IChDWzVdICsgMHgzNGQzNGQzNCArICgoQ1s0XSA+Pj4gMCkgPCAoQ19bNF0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1s2XSA9IChDWzZdICsgMHg0ZDM0ZDM0ZCArICgoQ1s1XSA+Pj4gMCkgPCAoQ19bNV0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgQ1s3XSA9IChDWzddICsgMHhkMzRkMzRkMyArICgoQ1s2XSA+Pj4gMCkgPCAoQ19bNl0gPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgdGhpcy5fYiA9IChDWzddID4+PiAwKSA8IChDX1s3XSA+Pj4gMCkgPyAxIDogMDtcblxuXHQgICAgICAgIC8vIENhbGN1bGF0ZSB0aGUgZy12YWx1ZXNcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDg7IGkrKykge1xuXHQgICAgICAgICAgICB2YXIgZ3ggPSBYW2ldICsgQ1tpXTtcblxuXHQgICAgICAgICAgICAvLyBDb25zdHJ1Y3QgaGlnaCBhbmQgbG93IGFyZ3VtZW50IGZvciBzcXVhcmluZ1xuXHQgICAgICAgICAgICB2YXIgZ2EgPSBneCAmIDB4ZmZmZjtcblx0ICAgICAgICAgICAgdmFyIGdiID0gZ3ggPj4+IDE2O1xuXG5cdCAgICAgICAgICAgIC8vIENhbGN1bGF0ZSBoaWdoIGFuZCBsb3cgcmVzdWx0IG9mIHNxdWFyaW5nXG5cdCAgICAgICAgICAgIHZhciBnaCA9ICgoKChnYSAqIGdhKSA+Pj4gMTcpICsgZ2EgKiBnYikgPj4+IDE1KSArIGdiICogZ2I7XG5cdCAgICAgICAgICAgIHZhciBnbCA9ICgoKGd4ICYgMHhmZmZmMDAwMCkgKiBneCkgfCAwKSArICgoKGd4ICYgMHgwMDAwZmZmZikgKiBneCkgfCAwKTtcblxuXHQgICAgICAgICAgICAvLyBIaWdoIFhPUiBsb3dcblx0ICAgICAgICAgICAgR1tpXSA9IGdoIF4gZ2w7XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gQ2FsY3VsYXRlIG5ldyBzdGF0ZSB2YWx1ZXNcblx0ICAgICAgICBYWzBdID0gKEdbMF0gKyAoKEdbN10gPDwgMTYpIHwgKEdbN10gPj4+IDE2KSkgKyAoKEdbNl0gPDwgMTYpIHwgKEdbNl0gPj4+IDE2KSkpIHwgMDtcblx0ICAgICAgICBYWzFdID0gKEdbMV0gKyAoKEdbMF0gPDwgOCkgIHwgKEdbMF0gPj4+IDI0KSkgKyBHWzddKSB8IDA7XG5cdCAgICAgICAgWFsyXSA9IChHWzJdICsgKChHWzFdIDw8IDE2KSB8IChHWzFdID4+PiAxNikpICsgKChHWzBdIDw8IDE2KSB8IChHWzBdID4+PiAxNikpKSB8IDA7XG5cdCAgICAgICAgWFszXSA9IChHWzNdICsgKChHWzJdIDw8IDgpICB8IChHWzJdID4+PiAyNCkpICsgR1sxXSkgfCAwO1xuXHQgICAgICAgIFhbNF0gPSAoR1s0XSArICgoR1szXSA8PCAxNikgfCAoR1szXSA+Pj4gMTYpKSArICgoR1syXSA8PCAxNikgfCAoR1syXSA+Pj4gMTYpKSkgfCAwO1xuXHQgICAgICAgIFhbNV0gPSAoR1s1XSArICgoR1s0XSA8PCA4KSAgfCAoR1s0XSA+Pj4gMjQpKSArIEdbM10pIHwgMDtcblx0ICAgICAgICBYWzZdID0gKEdbNl0gKyAoKEdbNV0gPDwgMTYpIHwgKEdbNV0gPj4+IDE2KSkgKyAoKEdbNF0gPDwgMTYpIHwgKEdbNF0gPj4+IDE2KSkpIHwgMDtcblx0ICAgICAgICBYWzddID0gKEdbN10gKyAoKEdbNl0gPDwgOCkgIHwgKEdbNl0gPj4+IDI0KSkgKyBHWzVdKSB8IDA7XG5cdCAgICB9XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb25zIHRvIHRoZSBjaXBoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0ID0gQ3J5cHRvSlMuUmFiYml0LmVuY3J5cHQobWVzc2FnZSwga2V5LCBjZmcpO1xuXHQgICAgICogICAgIHZhciBwbGFpbnRleHQgID0gQ3J5cHRvSlMuUmFiYml0LmRlY3J5cHQoY2lwaGVydGV4dCwga2V5LCBjZmcpO1xuXHQgICAgICovXG5cdCAgICBDLlJhYmJpdCA9IFN0cmVhbUNpcGhlci5fY3JlYXRlSGVscGVyKFJhYmJpdCk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuUmFiYml0O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2VuYy1iYXNlNjRcIiksIHJlcXVpcmUoXCIuL21kNVwiKSwgcmVxdWlyZShcIi4vZXZwa2RmXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9lbmMtYmFzZTY0XCIsIFwiLi9tZDVcIiwgXCIuL2V2cGtkZlwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBTdHJlYW1DaXBoZXIgPSBDX2xpYi5TdHJlYW1DaXBoZXI7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFJDNCBzdHJlYW0gY2lwaGVyIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFJDNCA9IENfYWxnby5SQzQgPSBTdHJlYW1DaXBoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGtleSA9IHRoaXMuX2tleTtcblx0ICAgICAgICAgICAgdmFyIGtleVdvcmRzID0ga2V5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIga2V5U2lnQnl0ZXMgPSBrZXkuc2lnQnl0ZXM7XG5cblx0ICAgICAgICAgICAgLy8gSW5pdCBzYm94XG5cdCAgICAgICAgICAgIHZhciBTID0gdGhpcy5fUyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI1NjsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICBTW2ldID0gaTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEtleSBzZXR1cFxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMCwgaiA9IDA7IGkgPCAyNTY7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgdmFyIGtleUJ5dGVJbmRleCA9IGkgJSBrZXlTaWdCeXRlcztcblx0ICAgICAgICAgICAgICAgIHZhciBrZXlCeXRlID0gKGtleVdvcmRzW2tleUJ5dGVJbmRleCA+Pj4gMl0gPj4+ICgyNCAtIChrZXlCeXRlSW5kZXggJSA0KSAqIDgpKSAmIDB4ZmY7XG5cblx0ICAgICAgICAgICAgICAgIGogPSAoaiArIFNbaV0gKyBrZXlCeXRlKSAlIDI1NjtcblxuXHQgICAgICAgICAgICAgICAgLy8gU3dhcFxuXHQgICAgICAgICAgICAgICAgdmFyIHQgPSBTW2ldO1xuXHQgICAgICAgICAgICAgICAgU1tpXSA9IFNbal07XG5cdCAgICAgICAgICAgICAgICBTW2pdID0gdDtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIENvdW50ZXJzXG5cdCAgICAgICAgICAgIHRoaXMuX2kgPSB0aGlzLl9qID0gMDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvUHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0XSBePSBnZW5lcmF0ZUtleXN0cmVhbVdvcmQuY2FsbCh0aGlzKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAga2V5U2l6ZTogMjU2LzMyLFxuXG5cdCAgICAgICAgaXZTaXplOiAwXG5cdCAgICB9KTtcblxuXHQgICAgZnVuY3Rpb24gZ2VuZXJhdGVLZXlzdHJlYW1Xb3JkKCkge1xuXHQgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgIHZhciBTID0gdGhpcy5fUztcblx0ICAgICAgICB2YXIgaSA9IHRoaXMuX2k7XG5cdCAgICAgICAgdmFyIGogPSB0aGlzLl9qO1xuXG5cdCAgICAgICAgLy8gR2VuZXJhdGUga2V5c3RyZWFtIHdvcmRcblx0ICAgICAgICB2YXIga2V5c3RyZWFtV29yZCA9IDA7XG5cdCAgICAgICAgZm9yICh2YXIgbiA9IDA7IG4gPCA0OyBuKyspIHtcblx0ICAgICAgICAgICAgaSA9IChpICsgMSkgJSAyNTY7XG5cdCAgICAgICAgICAgIGogPSAoaiArIFNbaV0pICUgMjU2O1xuXG5cdCAgICAgICAgICAgIC8vIFN3YXBcblx0ICAgICAgICAgICAgdmFyIHQgPSBTW2ldO1xuXHQgICAgICAgICAgICBTW2ldID0gU1tqXTtcblx0ICAgICAgICAgICAgU1tqXSA9IHQ7XG5cblx0ICAgICAgICAgICAga2V5c3RyZWFtV29yZCB8PSBTWyhTW2ldICsgU1tqXSkgJSAyNTZdIDw8ICgyNCAtIG4gKiA4KTtcblx0ICAgICAgICB9XG5cblx0ICAgICAgICAvLyBVcGRhdGUgY291bnRlcnNcblx0ICAgICAgICB0aGlzLl9pID0gaTtcblx0ICAgICAgICB0aGlzLl9qID0gajtcblxuXHQgICAgICAgIHJldHVybiBrZXlzdHJlYW1Xb3JkO1xuXHQgICAgfVxuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9ucyB0byB0aGUgY2lwaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgY2lwaGVydGV4dCA9IENyeXB0b0pTLlJDNC5lbmNyeXB0KG1lc3NhZ2UsIGtleSwgY2ZnKTtcblx0ICAgICAqICAgICB2YXIgcGxhaW50ZXh0ICA9IENyeXB0b0pTLlJDNC5kZWNyeXB0KGNpcGhlcnRleHQsIGtleSwgY2ZnKTtcblx0ICAgICAqL1xuXHQgICAgQy5SQzQgPSBTdHJlYW1DaXBoZXIuX2NyZWF0ZUhlbHBlcihSQzQpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIE1vZGlmaWVkIFJDNCBzdHJlYW0gY2lwaGVyIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFJDNERyb3AgPSBDX2FsZ28uUkM0RHJvcCA9IFJDNC5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmZpZ3VyYXRpb24gb3B0aW9ucy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBkcm9wIFRoZSBudW1iZXIgb2Yga2V5c3RyZWFtIHdvcmRzIHRvIGRyb3AuIERlZmF1bHQgMTkyXG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2ZnOiBSQzQuY2ZnLmV4dGVuZCh7XG5cdCAgICAgICAgICAgIGRyb3A6IDE5MlxuXHQgICAgICAgIH0pLFxuXG5cdCAgICAgICAgX2RvUmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgUkM0Ll9kb1Jlc2V0LmNhbGwodGhpcyk7XG5cblx0ICAgICAgICAgICAgLy8gRHJvcFxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gdGhpcy5jZmcuZHJvcDsgaSA+IDA7IGktLSkge1xuXHQgICAgICAgICAgICAgICAgZ2VuZXJhdGVLZXlzdHJlYW1Xb3JkLmNhbGwodGhpcyk7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbnMgdG8gdGhlIGNpcGhlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGNpcGhlcnRleHQgPSBDcnlwdG9KUy5SQzREcm9wLmVuY3J5cHQobWVzc2FnZSwga2V5LCBjZmcpO1xuXHQgICAgICogICAgIHZhciBwbGFpbnRleHQgID0gQ3J5cHRvSlMuUkM0RHJvcC5kZWNyeXB0KGNpcGhlcnRleHQsIGtleSwgY2ZnKTtcblx0ICAgICAqL1xuXHQgICAgQy5SQzREcm9wID0gU3RyZWFtQ2lwaGVyLl9jcmVhdGVIZWxwZXIoUkM0RHJvcCk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuUkM0O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKiogQHByZXNlcnZlXG5cdChjKSAyMDEyIGJ5IEPDqWRyaWMgTWVzbmlsLiBBbGwgcmlnaHRzIHJlc2VydmVkLlxuXG5cdFJlZGlzdHJpYnV0aW9uIGFuZCB1c2UgaW4gc291cmNlIGFuZCBiaW5hcnkgZm9ybXMsIHdpdGggb3Igd2l0aG91dCBtb2RpZmljYXRpb24sIGFyZSBwZXJtaXR0ZWQgcHJvdmlkZWQgdGhhdCB0aGUgZm9sbG93aW5nIGNvbmRpdGlvbnMgYXJlIG1ldDpcblxuXHQgICAgLSBSZWRpc3RyaWJ1dGlvbnMgb2Ygc291cmNlIGNvZGUgbXVzdCByZXRhaW4gdGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UsIHRoaXMgbGlzdCBvZiBjb25kaXRpb25zIGFuZCB0aGUgZm9sbG93aW5nIGRpc2NsYWltZXIuXG5cdCAgICAtIFJlZGlzdHJpYnV0aW9ucyBpbiBiaW5hcnkgZm9ybSBtdXN0IHJlcHJvZHVjZSB0aGUgYWJvdmUgY29weXJpZ2h0IG5vdGljZSwgdGhpcyBsaXN0IG9mIGNvbmRpdGlvbnMgYW5kIHRoZSBmb2xsb3dpbmcgZGlzY2xhaW1lciBpbiB0aGUgZG9jdW1lbnRhdGlvbiBhbmQvb3Igb3RoZXIgbWF0ZXJpYWxzIHByb3ZpZGVkIHdpdGggdGhlIGRpc3RyaWJ1dGlvbi5cblxuXHRUSElTIFNPRlRXQVJFIElTIFBST1ZJREVEIEJZIFRIRSBDT1BZUklHSFQgSE9MREVSUyBBTkQgQ09OVFJJQlVUT1JTIFwiQVMgSVNcIiBBTkQgQU5ZIEVYUFJFU1MgT1IgSU1QTElFRCBXQVJSQU5USUVTLCBJTkNMVURJTkcsIEJVVCBOT1QgTElNSVRFRCBUTywgVEhFIElNUExJRUQgV0FSUkFOVElFUyBPRiBNRVJDSEFOVEFCSUxJVFkgQU5EIEZJVE5FU1MgRk9SIEEgUEFSVElDVUxBUiBQVVJQT1NFIEFSRSBESVNDTEFJTUVELiBJTiBOTyBFVkVOVCBTSEFMTCBUSEUgQ09QWVJJR0hUIEhPTERFUiBPUiBDT05UUklCVVRPUlMgQkUgTElBQkxFIEZPUiBBTlkgRElSRUNULCBJTkRJUkVDVCwgSU5DSURFTlRBTCwgU1BFQ0lBTCwgRVhFTVBMQVJZLCBPUiBDT05TRVFVRU5USUFMIERBTUFHRVMgKElOQ0xVRElORywgQlVUIE5PVCBMSU1JVEVEIFRPLCBQUk9DVVJFTUVOVCBPRiBTVUJTVElUVVRFIEdPT0RTIE9SIFNFUlZJQ0VTOyBMT1NTIE9GIFVTRSwgREFUQSwgT1IgUFJPRklUUzsgT1IgQlVTSU5FU1MgSU5URVJSVVBUSU9OKSBIT1dFVkVSIENBVVNFRCBBTkQgT04gQU5ZIFRIRU9SWSBPRiBMSUFCSUxJVFksIFdIRVRIRVIgSU4gQ09OVFJBQ1QsIFNUUklDVCBMSUFCSUxJVFksIE9SIFRPUlQgKElOQ0xVRElORyBORUdMSUdFTkNFIE9SIE9USEVSV0lTRSkgQVJJU0lORyBJTiBBTlkgV0FZIE9VVCBPRiBUSEUgVVNFIE9GIFRISVMgU09GVFdBUkUsIEVWRU4gSUYgQURWSVNFRCBPRiBUSEUgUE9TU0lCSUxJVFkgT0YgU1VDSCBEQU1BR0UuXG5cdCovXG5cblx0KGZ1bmN0aW9uIChNYXRoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgSGFzaGVyID0gQ19saWIuSGFzaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gQ29uc3RhbnRzIHRhYmxlXG5cdCAgICB2YXIgX3psID0gV29yZEFycmF5LmNyZWF0ZShbXG5cdCAgICAgICAgMCwgIDEsICAyLCAgMywgIDQsICA1LCAgNiwgIDcsICA4LCAgOSwgMTAsIDExLCAxMiwgMTMsIDE0LCAxNSxcblx0ICAgICAgICA3LCAgNCwgMTMsICAxLCAxMCwgIDYsIDE1LCAgMywgMTIsICAwLCAgOSwgIDUsICAyLCAxNCwgMTEsICA4LFxuXHQgICAgICAgIDMsIDEwLCAxNCwgIDQsICA5LCAxNSwgIDgsICAxLCAgMiwgIDcsICAwLCAgNiwgMTMsIDExLCAgNSwgMTIsXG5cdCAgICAgICAgMSwgIDksIDExLCAxMCwgIDAsICA4LCAxMiwgIDQsIDEzLCAgMywgIDcsIDE1LCAxNCwgIDUsICA2LCAgMixcblx0ICAgICAgICA0LCAgMCwgIDUsICA5LCAgNywgMTIsICAyLCAxMCwgMTQsICAxLCAgMywgIDgsIDExLCAgNiwgMTUsIDEzXSk7XG5cdCAgICB2YXIgX3pyID0gV29yZEFycmF5LmNyZWF0ZShbXG5cdCAgICAgICAgNSwgMTQsICA3LCAgMCwgIDksICAyLCAxMSwgIDQsIDEzLCAgNiwgMTUsICA4LCAgMSwgMTAsICAzLCAxMixcblx0ICAgICAgICA2LCAxMSwgIDMsICA3LCAgMCwgMTMsICA1LCAxMCwgMTQsIDE1LCAgOCwgMTIsICA0LCAgOSwgIDEsICAyLFxuXHQgICAgICAgIDE1LCAgNSwgIDEsICAzLCAgNywgMTQsICA2LCAgOSwgMTEsICA4LCAxMiwgIDIsIDEwLCAgMCwgIDQsIDEzLFxuXHQgICAgICAgIDgsICA2LCAgNCwgIDEsICAzLCAxMSwgMTUsICAwLCAgNSwgMTIsICAyLCAxMywgIDksICA3LCAxMCwgMTQsXG5cdCAgICAgICAgMTIsIDE1LCAxMCwgIDQsICAxLCAgNSwgIDgsICA3LCAgNiwgIDIsIDEzLCAxNCwgIDAsICAzLCAgOSwgMTFdKTtcblx0ICAgIHZhciBfc2wgPSBXb3JkQXJyYXkuY3JlYXRlKFtcblx0ICAgICAgICAgMTEsIDE0LCAxNSwgMTIsICA1LCAgOCwgIDcsICA5LCAxMSwgMTMsIDE0LCAxNSwgIDYsICA3LCAgOSwgIDgsXG5cdCAgICAgICAgNywgNiwgICA4LCAxMywgMTEsICA5LCAgNywgMTUsICA3LCAxMiwgMTUsICA5LCAxMSwgIDcsIDEzLCAxMixcblx0ICAgICAgICAxMSwgMTMsICA2LCAgNywgMTQsICA5LCAxMywgMTUsIDE0LCAgOCwgMTMsICA2LCAgNSwgMTIsICA3LCAgNSxcblx0ICAgICAgICAgIDExLCAxMiwgMTQsIDE1LCAxNCwgMTUsICA5LCAgOCwgIDksIDE0LCAgNSwgIDYsICA4LCAgNiwgIDUsIDEyLFxuXHQgICAgICAgIDksIDE1LCAgNSwgMTEsICA2LCAgOCwgMTMsIDEyLCAgNSwgMTIsIDEzLCAxNCwgMTEsICA4LCAgNSwgIDYgXSk7XG5cdCAgICB2YXIgX3NyID0gV29yZEFycmF5LmNyZWF0ZShbXG5cdCAgICAgICAgOCwgIDksICA5LCAxMSwgMTMsIDE1LCAxNSwgIDUsICA3LCAgNywgIDgsIDExLCAxNCwgMTQsIDEyLCAgNixcblx0ICAgICAgICA5LCAxMywgMTUsICA3LCAxMiwgIDgsICA5LCAxMSwgIDcsICA3LCAxMiwgIDcsICA2LCAxNSwgMTMsIDExLFxuXHQgICAgICAgIDksICA3LCAxNSwgMTEsICA4LCAgNiwgIDYsIDE0LCAxMiwgMTMsICA1LCAxNCwgMTMsIDEzLCAgNywgIDUsXG5cdCAgICAgICAgMTUsICA1LCAgOCwgMTEsIDE0LCAxNCwgIDYsIDE0LCAgNiwgIDksIDEyLCAgOSwgMTIsICA1LCAxNSwgIDgsXG5cdCAgICAgICAgOCwgIDUsIDEyLCAgOSwgMTIsICA1LCAxNCwgIDYsICA4LCAxMywgIDYsICA1LCAxNSwgMTMsIDExLCAxMSBdKTtcblxuXHQgICAgdmFyIF9obCA9ICBXb3JkQXJyYXkuY3JlYXRlKFsgMHgwMDAwMDAwMCwgMHg1QTgyNzk5OSwgMHg2RUQ5RUJBMSwgMHg4RjFCQkNEQywgMHhBOTUzRkQ0RV0pO1xuXHQgICAgdmFyIF9ociA9ICBXb3JkQXJyYXkuY3JlYXRlKFsgMHg1MEEyOEJFNiwgMHg1QzRERDEyNCwgMHg2RDcwM0VGMywgMHg3QTZENzZFOSwgMHgwMDAwMDAwMF0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFJJUEVNRDE2MCBoYXNoIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFJJUEVNRDE2MCA9IENfYWxnby5SSVBFTUQxNjAgPSBIYXNoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB0aGlzLl9oYXNoICA9IFdvcmRBcnJheS5jcmVhdGUoWzB4Njc0NTIzMDEsIDB4RUZDREFCODksIDB4OThCQURDRkUsIDB4MTAzMjU0NzYsIDB4QzNEMkUxRjBdKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvUHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cblx0ICAgICAgICAgICAgLy8gU3dhcCBlbmRpYW5cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgIHZhciBvZmZzZXRfaSA9IG9mZnNldCArIGk7XG5cdCAgICAgICAgICAgICAgICB2YXIgTV9vZmZzZXRfaSA9IE1bb2Zmc2V0X2ldO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBTd2FwXG5cdCAgICAgICAgICAgICAgICBNW29mZnNldF9pXSA9IChcblx0ICAgICAgICAgICAgICAgICAgICAoKChNX29mZnNldF9pIDw8IDgpICB8IChNX29mZnNldF9pID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgICAgICgoKE1fb2Zmc2V0X2kgPDwgMjQpIHwgKE1fb2Zmc2V0X2kgPj4+IDgpKSAgJiAweGZmMDBmZjAwKVxuXHQgICAgICAgICAgICAgICAgKTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgSCAgPSB0aGlzLl9oYXNoLndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgaGwgPSBfaGwud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBociA9IF9oci53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHpsID0gX3psLndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgenIgPSBfenIud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBzbCA9IF9zbC53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHNyID0gX3NyLndvcmRzO1xuXG5cdCAgICAgICAgICAgIC8vIFdvcmtpbmcgdmFyaWFibGVzXG5cdCAgICAgICAgICAgIHZhciBhbCwgYmwsIGNsLCBkbCwgZWw7XG5cdCAgICAgICAgICAgIHZhciBhciwgYnIsIGNyLCBkciwgZXI7XG5cblx0ICAgICAgICAgICAgYXIgPSBhbCA9IEhbMF07XG5cdCAgICAgICAgICAgIGJyID0gYmwgPSBIWzFdO1xuXHQgICAgICAgICAgICBjciA9IGNsID0gSFsyXTtcblx0ICAgICAgICAgICAgZHIgPSBkbCA9IEhbM107XG5cdCAgICAgICAgICAgIGVyID0gZWwgPSBIWzRdO1xuXHQgICAgICAgICAgICAvLyBDb21wdXRhdGlvblxuXHQgICAgICAgICAgICB2YXIgdDtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4MDsgaSArPSAxKSB7XG5cdCAgICAgICAgICAgICAgICB0ID0gKGFsICsgIE1bb2Zmc2V0K3psW2ldXSl8MDtcblx0ICAgICAgICAgICAgICAgIGlmIChpPDE2KXtcblx0XHQgICAgICAgICAgICB0ICs9ICBmMShibCxjbCxkbCkgKyBobFswXTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoaTwzMikge1xuXHRcdCAgICAgICAgICAgIHQgKz0gIGYyKGJsLGNsLGRsKSArIGhsWzFdO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChpPDQ4KSB7XG5cdFx0ICAgICAgICAgICAgdCArPSAgZjMoYmwsY2wsZGwpICsgaGxbMl07XG5cdCAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKGk8NjQpIHtcblx0XHQgICAgICAgICAgICB0ICs9ICBmNChibCxjbCxkbCkgKyBobFszXTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSB7Ly8gaWYgKGk8ODApIHtcblx0XHQgICAgICAgICAgICB0ICs9ICBmNShibCxjbCxkbCkgKyBobFs0XTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIHQgPSB0fDA7XG5cdCAgICAgICAgICAgICAgICB0ID0gIHJvdGwodCxzbFtpXSk7XG5cdCAgICAgICAgICAgICAgICB0ID0gKHQrZWwpfDA7XG5cdCAgICAgICAgICAgICAgICBhbCA9IGVsO1xuXHQgICAgICAgICAgICAgICAgZWwgPSBkbDtcblx0ICAgICAgICAgICAgICAgIGRsID0gcm90bChjbCwgMTApO1xuXHQgICAgICAgICAgICAgICAgY2wgPSBibDtcblx0ICAgICAgICAgICAgICAgIGJsID0gdDtcblxuXHQgICAgICAgICAgICAgICAgdCA9IChhciArIE1bb2Zmc2V0K3pyW2ldXSl8MDtcblx0ICAgICAgICAgICAgICAgIGlmIChpPDE2KXtcblx0XHQgICAgICAgICAgICB0ICs9ICBmNShicixjcixkcikgKyBoclswXTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoaTwzMikge1xuXHRcdCAgICAgICAgICAgIHQgKz0gIGY0KGJyLGNyLGRyKSArIGhyWzFdO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChpPDQ4KSB7XG5cdFx0ICAgICAgICAgICAgdCArPSAgZjMoYnIsY3IsZHIpICsgaHJbMl07XG5cdCAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKGk8NjQpIHtcblx0XHQgICAgICAgICAgICB0ICs9ICBmMihicixjcixkcikgKyBoclszXTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSB7Ly8gaWYgKGk8ODApIHtcblx0XHQgICAgICAgICAgICB0ICs9ICBmMShicixjcixkcikgKyBocls0XTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIHQgPSB0fDA7XG5cdCAgICAgICAgICAgICAgICB0ID0gIHJvdGwodCxzcltpXSkgO1xuXHQgICAgICAgICAgICAgICAgdCA9ICh0K2VyKXwwO1xuXHQgICAgICAgICAgICAgICAgYXIgPSBlcjtcblx0ICAgICAgICAgICAgICAgIGVyID0gZHI7XG5cdCAgICAgICAgICAgICAgICBkciA9IHJvdGwoY3IsIDEwKTtcblx0ICAgICAgICAgICAgICAgIGNyID0gYnI7XG5cdCAgICAgICAgICAgICAgICBiciA9IHQ7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgLy8gSW50ZXJtZWRpYXRlIGhhc2ggdmFsdWVcblx0ICAgICAgICAgICAgdCAgICA9IChIWzFdICsgY2wgKyBkcil8MDtcblx0ICAgICAgICAgICAgSFsxXSA9IChIWzJdICsgZGwgKyBlcil8MDtcblx0ICAgICAgICAgICAgSFsyXSA9IChIWzNdICsgZWwgKyBhcil8MDtcblx0ICAgICAgICAgICAgSFszXSA9IChIWzRdICsgYWwgKyBicil8MDtcblx0ICAgICAgICAgICAgSFs0XSA9IChIWzBdICsgYmwgKyBjcil8MDtcblx0ICAgICAgICAgICAgSFswXSA9ICB0O1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9GaW5hbGl6ZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGRhdGEgPSB0aGlzLl9kYXRhO1xuXHQgICAgICAgICAgICB2YXIgZGF0YVdvcmRzID0gZGF0YS53b3JkcztcblxuXHQgICAgICAgICAgICB2YXIgbkJpdHNUb3RhbCA9IHRoaXMuX25EYXRhQnl0ZXMgKiA4O1xuXHQgICAgICAgICAgICB2YXIgbkJpdHNMZWZ0ID0gZGF0YS5zaWdCeXRlcyAqIDg7XG5cblx0ICAgICAgICAgICAgLy8gQWRkIHBhZGRpbmdcblx0ICAgICAgICAgICAgZGF0YVdvcmRzW25CaXRzTGVmdCA+Pj4gNV0gfD0gMHg4MCA8PCAoMjQgLSBuQml0c0xlZnQgJSAzMik7XG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1soKChuQml0c0xlZnQgKyA2NCkgPj4+IDkpIDw8IDQpICsgMTRdID0gKFxuXHQgICAgICAgICAgICAgICAgKCgobkJpdHNUb3RhbCA8PCA4KSAgfCAobkJpdHNUb3RhbCA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICgoKG5CaXRzVG90YWwgPDwgMjQpIHwgKG5CaXRzVG90YWwgPj4+IDgpKSAgJiAweGZmMDBmZjAwKVxuXHQgICAgICAgICAgICApO1xuXHQgICAgICAgICAgICBkYXRhLnNpZ0J5dGVzID0gKGRhdGFXb3Jkcy5sZW5ndGggKyAxKSAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gSGFzaCBmaW5hbCBibG9ja3Ncblx0ICAgICAgICAgICAgdGhpcy5fcHJvY2VzcygpO1xuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgaGFzaCA9IHRoaXMuX2hhc2g7XG5cdCAgICAgICAgICAgIHZhciBIID0gaGFzaC53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBTd2FwIGVuZGlhblxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgICAgIHZhciBIX2kgPSBIW2ldO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBTd2FwXG5cdCAgICAgICAgICAgICAgICBIW2ldID0gKCgoSF9pIDw8IDgpICB8IChIX2kgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8XG5cdCAgICAgICAgICAgICAgICAgICAgICAgKCgoSF9pIDw8IDI0KSB8IChIX2kgPj4+IDgpKSAgJiAweGZmMDBmZjAwKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFJldHVybiBmaW5hbCBjb21wdXRlZCBoYXNoXG5cdCAgICAgICAgICAgIHJldHVybiBoYXNoO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBIYXNoZXIuY2xvbmUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgY2xvbmUuX2hhc2ggPSB0aGlzLl9oYXNoLmNsb25lKCk7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGNsb25lO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cblx0ICAgIGZ1bmN0aW9uIGYxKHgsIHksIHopIHtcblx0ICAgICAgICByZXR1cm4gKCh4KSBeICh5KSBeICh6KSk7XG5cblx0ICAgIH1cblxuXHQgICAgZnVuY3Rpb24gZjIoeCwgeSwgeikge1xuXHQgICAgICAgIHJldHVybiAoKCh4KSYoeSkpIHwgKCh+eCkmKHopKSk7XG5cdCAgICB9XG5cblx0ICAgIGZ1bmN0aW9uIGYzKHgsIHksIHopIHtcblx0ICAgICAgICByZXR1cm4gKCgoeCkgfCAofih5KSkpIF4gKHopKTtcblx0ICAgIH1cblxuXHQgICAgZnVuY3Rpb24gZjQoeCwgeSwgeikge1xuXHQgICAgICAgIHJldHVybiAoKCh4KSAmICh6KSkgfCAoKHkpJih+KHopKSkpO1xuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiBmNSh4LCB5LCB6KSB7XG5cdCAgICAgICAgcmV0dXJuICgoeCkgXiAoKHkpIHwofih6KSkpKTtcblxuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiByb3RsKHgsbikge1xuXHQgICAgICAgIHJldHVybiAoeDw8bikgfCAoeD4+PigzMi1uKSk7XG5cdCAgICB9XG5cblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgaGFzaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlJJUEVNRDE2MCgnbWVzc2FnZScpO1xuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuUklQRU1EMTYwKHdvcmRBcnJheSk7XG5cdCAgICAgKi9cblx0ICAgIEMuUklQRU1EMTYwID0gSGFzaGVyLl9jcmVhdGVIZWxwZXIoUklQRU1EMTYwKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgSE1BQydzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IGtleSBUaGUgc2VjcmV0IGtleS5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBITUFDLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaG1hYyA9IENyeXB0b0pTLkhtYWNSSVBFTUQxNjAobWVzc2FnZSwga2V5KTtcblx0ICAgICAqL1xuXHQgICAgQy5IbWFjUklQRU1EMTYwID0gSGFzaGVyLl9jcmVhdGVIbWFjSGVscGVyKFJJUEVNRDE2MCk7XG5cdH0oTWF0aCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLlJJUEVNRDE2MDtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uICgpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIFdvcmRBcnJheSA9IENfbGliLldvcmRBcnJheTtcblx0ICAgIHZhciBIYXNoZXIgPSBDX2xpYi5IYXNoZXI7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICAvLyBSZXVzYWJsZSBvYmplY3Rcblx0ICAgIHZhciBXID0gW107XG5cblx0ICAgIC8qKlxuXHQgICAgICogU0hBLTEgaGFzaCBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBTSEExID0gQ19hbGdvLlNIQTEgPSBIYXNoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB0aGlzLl9oYXNoID0gbmV3IFdvcmRBcnJheS5pbml0KFtcblx0ICAgICAgICAgICAgICAgIDB4Njc0NTIzMDEsIDB4ZWZjZGFiODksXG5cdCAgICAgICAgICAgICAgICAweDk4YmFkY2ZlLCAweDEwMzI1NDc2LFxuXHQgICAgICAgICAgICAgICAgMHhjM2QyZTFmMFxuXHQgICAgICAgICAgICBdKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvUHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBIID0gdGhpcy5faGFzaC53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBXb3JraW5nIHZhcmlhYmxlc1xuXHQgICAgICAgICAgICB2YXIgYSA9IEhbMF07XG5cdCAgICAgICAgICAgIHZhciBiID0gSFsxXTtcblx0ICAgICAgICAgICAgdmFyIGMgPSBIWzJdO1xuXHQgICAgICAgICAgICB2YXIgZCA9IEhbM107XG5cdCAgICAgICAgICAgIHZhciBlID0gSFs0XTtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRhdGlvblxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDgwOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIGlmIChpIDwgMTYpIHtcblx0ICAgICAgICAgICAgICAgICAgICBXW2ldID0gTVtvZmZzZXQgKyBpXSB8IDA7XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBuID0gV1tpIC0gM10gXiBXW2kgLSA4XSBeIFdbaSAtIDE0XSBeIFdbaSAtIDE2XTtcblx0ICAgICAgICAgICAgICAgICAgICBXW2ldID0gKG4gPDwgMSkgfCAobiA+Pj4gMzEpO1xuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICB2YXIgdCA9ICgoYSA8PCA1KSB8IChhID4+PiAyNykpICsgZSArIFdbaV07XG5cdCAgICAgICAgICAgICAgICBpZiAoaSA8IDIwKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdCArPSAoKGIgJiBjKSB8ICh+YiAmIGQpKSArIDB4NWE4Mjc5OTk7XG5cdCAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKGkgPCA0MCkge1xuXHQgICAgICAgICAgICAgICAgICAgIHQgKz0gKGIgXiBjIF4gZCkgKyAweDZlZDllYmExO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChpIDwgNjApIHtcblx0ICAgICAgICAgICAgICAgICAgICB0ICs9ICgoYiAmIGMpIHwgKGIgJiBkKSB8IChjICYgZCkpIC0gMHg3MGU0NDMyNDtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSAvKiBpZiAoaSA8IDgwKSAqLyB7XG5cdCAgICAgICAgICAgICAgICAgICAgdCArPSAoYiBeIGMgXiBkKSAtIDB4MzU5ZDNlMmE7XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIGUgPSBkO1xuXHQgICAgICAgICAgICAgICAgZCA9IGM7XG5cdCAgICAgICAgICAgICAgICBjID0gKGIgPDwgMzApIHwgKGIgPj4+IDIpO1xuXHQgICAgICAgICAgICAgICAgYiA9IGE7XG5cdCAgICAgICAgICAgICAgICBhID0gdDtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEludGVybWVkaWF0ZSBoYXNoIHZhbHVlXG5cdCAgICAgICAgICAgIEhbMF0gPSAoSFswXSArIGEpIHwgMDtcblx0ICAgICAgICAgICAgSFsxXSA9IChIWzFdICsgYikgfCAwO1xuXHQgICAgICAgICAgICBIWzJdID0gKEhbMl0gKyBjKSB8IDA7XG5cdCAgICAgICAgICAgIEhbM10gPSAoSFszXSArIGQpIHwgMDtcblx0ICAgICAgICAgICAgSFs0XSA9IChIWzRdICsgZSkgfCAwO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9GaW5hbGl6ZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGRhdGEgPSB0aGlzLl9kYXRhO1xuXHQgICAgICAgICAgICB2YXIgZGF0YVdvcmRzID0gZGF0YS53b3JkcztcblxuXHQgICAgICAgICAgICB2YXIgbkJpdHNUb3RhbCA9IHRoaXMuX25EYXRhQnl0ZXMgKiA4O1xuXHQgICAgICAgICAgICB2YXIgbkJpdHNMZWZ0ID0gZGF0YS5zaWdCeXRlcyAqIDg7XG5cblx0ICAgICAgICAgICAgLy8gQWRkIHBhZGRpbmdcblx0ICAgICAgICAgICAgZGF0YVdvcmRzW25CaXRzTGVmdCA+Pj4gNV0gfD0gMHg4MCA8PCAoMjQgLSBuQml0c0xlZnQgJSAzMik7XG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1soKChuQml0c0xlZnQgKyA2NCkgPj4+IDkpIDw8IDQpICsgMTRdID0gTWF0aC5mbG9vcihuQml0c1RvdGFsIC8gMHgxMDAwMDAwMDApO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKCgobkJpdHNMZWZ0ICsgNjQpID4+PiA5KSA8PCA0KSArIDE1XSA9IG5CaXRzVG90YWw7XG5cdCAgICAgICAgICAgIGRhdGEuc2lnQnl0ZXMgPSBkYXRhV29yZHMubGVuZ3RoICogNDtcblxuXHQgICAgICAgICAgICAvLyBIYXNoIGZpbmFsIGJsb2Nrc1xuXHQgICAgICAgICAgICB0aGlzLl9wcm9jZXNzKCk7XG5cblx0ICAgICAgICAgICAgLy8gUmV0dXJuIGZpbmFsIGNvbXB1dGVkIGhhc2hcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXMuX2hhc2g7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGNsb25lOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHZhciBjbG9uZSA9IEhhc2hlci5jbG9uZS5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICBjbG9uZS5faGFzaCA9IHRoaXMuX2hhc2guY2xvbmUoKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gY2xvbmU7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIGhhc2hlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5TSEExKCdtZXNzYWdlJyk7XG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5TSEExKHdvcmRBcnJheSk7XG5cdCAgICAgKi9cblx0ICAgIEMuU0hBMSA9IEhhc2hlci5fY3JlYXRlSGVscGVyKFNIQTEpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBITUFDJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30ga2V5IFRoZSBzZWNyZXQga2V5LlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIEhNQUMuXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBobWFjID0gQ3J5cHRvSlMuSG1hY1NIQTEobWVzc2FnZSwga2V5KTtcblx0ICAgICAqL1xuXHQgICAgQy5IbWFjU0hBMSA9IEhhc2hlci5fY3JlYXRlSG1hY0hlbHBlcihTSEExKTtcblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5TSEExO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL3NoYTI1NlwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9zaGEyNTZcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXHQgICAgdmFyIFNIQTI1NiA9IENfYWxnby5TSEEyNTY7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU0hBLTIyNCBoYXNoIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFNIQTIyNCA9IENfYWxnby5TSEEyMjQgPSBTSEEyNTYuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB0aGlzLl9oYXNoID0gbmV3IFdvcmRBcnJheS5pbml0KFtcblx0ICAgICAgICAgICAgICAgIDB4YzEwNTllZDgsIDB4MzY3Y2Q1MDcsIDB4MzA3MGRkMTcsIDB4ZjcwZTU5MzksXG5cdCAgICAgICAgICAgICAgICAweGZmYzAwYjMxLCAweDY4NTgxNTExLCAweDY0Zjk4ZmE3LCAweGJlZmE0ZmE0XG5cdCAgICAgICAgICAgIF0pO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9GaW5hbGl6ZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgaGFzaCA9IFNIQTI1Ni5fZG9GaW5hbGl6ZS5jYWxsKHRoaXMpO1xuXG5cdCAgICAgICAgICAgIGhhc2guc2lnQnl0ZXMgLT0gNDtcblxuXHQgICAgICAgICAgICByZXR1cm4gaGFzaDtcblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgaGFzaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlNIQTIyNCgnbWVzc2FnZScpO1xuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBMjI0KHdvcmRBcnJheSk7XG5cdCAgICAgKi9cblx0ICAgIEMuU0hBMjI0ID0gU0hBMjU2Ll9jcmVhdGVIZWxwZXIoU0hBMjI0KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgSE1BQydzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IGtleSBUaGUgc2VjcmV0IGtleS5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBITUFDLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaG1hYyA9IENyeXB0b0pTLkhtYWNTSEEyMjQobWVzc2FnZSwga2V5KTtcblx0ICAgICAqL1xuXHQgICAgQy5IbWFjU0hBMjI0ID0gU0hBMjU2Ll9jcmVhdGVIbWFjSGVscGVyKFNIQTIyNCk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuU0hBMjI0O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKE1hdGgpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIFdvcmRBcnJheSA9IENfbGliLldvcmRBcnJheTtcblx0ICAgIHZhciBIYXNoZXIgPSBDX2xpYi5IYXNoZXI7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICAvLyBJbml0aWFsaXphdGlvbiBhbmQgcm91bmQgY29uc3RhbnRzIHRhYmxlc1xuXHQgICAgdmFyIEggPSBbXTtcblx0ICAgIHZhciBLID0gW107XG5cblx0ICAgIC8vIENvbXB1dGUgY29uc3RhbnRzXG5cdCAgICAoZnVuY3Rpb24gKCkge1xuXHQgICAgICAgIGZ1bmN0aW9uIGlzUHJpbWUobikge1xuXHQgICAgICAgICAgICB2YXIgc3FydE4gPSBNYXRoLnNxcnQobik7XG5cdCAgICAgICAgICAgIGZvciAodmFyIGZhY3RvciA9IDI7IGZhY3RvciA8PSBzcXJ0TjsgZmFjdG9yKyspIHtcblx0ICAgICAgICAgICAgICAgIGlmICghKG4gJSBmYWN0b3IpKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIHRydWU7XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgZnVuY3Rpb24gZ2V0RnJhY3Rpb25hbEJpdHMobikge1xuXHQgICAgICAgICAgICByZXR1cm4gKChuIC0gKG4gfCAwKSkgKiAweDEwMDAwMDAwMCkgfCAwO1xuXHQgICAgICAgIH1cblxuXHQgICAgICAgIHZhciBuID0gMjtcblx0ICAgICAgICB2YXIgblByaW1lID0gMDtcblx0ICAgICAgICB3aGlsZSAoblByaW1lIDwgNjQpIHtcblx0ICAgICAgICAgICAgaWYgKGlzUHJpbWUobikpIHtcblx0ICAgICAgICAgICAgICAgIGlmIChuUHJpbWUgPCA4KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgSFtuUHJpbWVdID0gZ2V0RnJhY3Rpb25hbEJpdHMoTWF0aC5wb3cobiwgMSAvIDIpKTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIEtbblByaW1lXSA9IGdldEZyYWN0aW9uYWxCaXRzKE1hdGgucG93KG4sIDEgLyAzKSk7XG5cblx0ICAgICAgICAgICAgICAgIG5QcmltZSsrO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgbisrO1xuXHQgICAgICAgIH1cblx0ICAgIH0oKSk7XG5cblx0ICAgIC8vIFJldXNhYmxlIG9iamVjdFxuXHQgICAgdmFyIFcgPSBbXTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTSEEtMjU2IGhhc2ggYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgU0hBMjU2ID0gQ19hbGdvLlNIQTI1NiA9IEhhc2hlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHRoaXMuX2hhc2ggPSBuZXcgV29yZEFycmF5LmluaXQoSC5zbGljZSgwKSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgSCA9IHRoaXMuX2hhc2gud29yZHM7XG5cblx0ICAgICAgICAgICAgLy8gV29ya2luZyB2YXJpYWJsZXNcblx0ICAgICAgICAgICAgdmFyIGEgPSBIWzBdO1xuXHQgICAgICAgICAgICB2YXIgYiA9IEhbMV07XG5cdCAgICAgICAgICAgIHZhciBjID0gSFsyXTtcblx0ICAgICAgICAgICAgdmFyIGQgPSBIWzNdO1xuXHQgICAgICAgICAgICB2YXIgZSA9IEhbNF07XG5cdCAgICAgICAgICAgIHZhciBmID0gSFs1XTtcblx0ICAgICAgICAgICAgdmFyIGcgPSBIWzZdO1xuXHQgICAgICAgICAgICB2YXIgaCA9IEhbN107XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0YXRpb25cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA2NDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICBpZiAoaSA8IDE2KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgV1tpXSA9IE1bb2Zmc2V0ICsgaV0gfCAwO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgZ2FtbWEweCA9IFdbaSAtIDE1XTtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgZ2FtbWEwICA9ICgoZ2FtbWEweCA8PCAyNSkgfCAoZ2FtbWEweCA+Pj4gNykpICBeXG5cdCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAoKGdhbW1hMHggPDwgMTQpIHwgKGdhbW1hMHggPj4+IDE4KSkgXlxuXHQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIChnYW1tYTB4ID4+PiAzKTtcblxuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTF4ID0gV1tpIC0gMl07XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMSAgPSAoKGdhbW1hMXggPDwgMTUpIHwgKGdhbW1hMXggPj4+IDE3KSkgXlxuXHQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKChnYW1tYTF4IDw8IDEzKSB8IChnYW1tYTF4ID4+PiAxOSkpIF5cblx0ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAoZ2FtbWExeCA+Pj4gMTApO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgV1tpXSA9IGdhbW1hMCArIFdbaSAtIDddICsgZ2FtbWExICsgV1tpIC0gMTZdO1xuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICB2YXIgY2ggID0gKGUgJiBmKSBeICh+ZSAmIGcpO1xuXHQgICAgICAgICAgICAgICAgdmFyIG1haiA9IChhICYgYikgXiAoYSAmIGMpIF4gKGIgJiBjKTtcblxuXHQgICAgICAgICAgICAgICAgdmFyIHNpZ21hMCA9ICgoYSA8PCAzMCkgfCAoYSA+Pj4gMikpIF4gKChhIDw8IDE5KSB8IChhID4+PiAxMykpIF4gKChhIDw8IDEwKSB8IChhID4+PiAyMikpO1xuXHQgICAgICAgICAgICAgICAgdmFyIHNpZ21hMSA9ICgoZSA8PCAyNikgfCAoZSA+Pj4gNikpIF4gKChlIDw8IDIxKSB8IChlID4+PiAxMSkpIF4gKChlIDw8IDcpICB8IChlID4+PiAyNSkpO1xuXG5cdCAgICAgICAgICAgICAgICB2YXIgdDEgPSBoICsgc2lnbWExICsgY2ggKyBLW2ldICsgV1tpXTtcblx0ICAgICAgICAgICAgICAgIHZhciB0MiA9IHNpZ21hMCArIG1hajtcblxuXHQgICAgICAgICAgICAgICAgaCA9IGc7XG5cdCAgICAgICAgICAgICAgICBnID0gZjtcblx0ICAgICAgICAgICAgICAgIGYgPSBlO1xuXHQgICAgICAgICAgICAgICAgZSA9IChkICsgdDEpIHwgMDtcblx0ICAgICAgICAgICAgICAgIGQgPSBjO1xuXHQgICAgICAgICAgICAgICAgYyA9IGI7XG5cdCAgICAgICAgICAgICAgICBiID0gYTtcblx0ICAgICAgICAgICAgICAgIGEgPSAodDEgKyB0MikgfCAwO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gSW50ZXJtZWRpYXRlIGhhc2ggdmFsdWVcblx0ICAgICAgICAgICAgSFswXSA9IChIWzBdICsgYSkgfCAwO1xuXHQgICAgICAgICAgICBIWzFdID0gKEhbMV0gKyBiKSB8IDA7XG5cdCAgICAgICAgICAgIEhbMl0gPSAoSFsyXSArIGMpIHwgMDtcblx0ICAgICAgICAgICAgSFszXSA9IChIWzNdICsgZCkgfCAwO1xuXHQgICAgICAgICAgICBIWzRdID0gKEhbNF0gKyBlKSB8IDA7XG5cdCAgICAgICAgICAgIEhbNV0gPSAoSFs1XSArIGYpIHwgMDtcblx0ICAgICAgICAgICAgSFs2XSA9IChIWzZdICsgZykgfCAwO1xuXHQgICAgICAgICAgICBIWzddID0gKEhbN10gKyBoKSB8IDA7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0ZpbmFsaXplOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgZGF0YSA9IHRoaXMuX2RhdGE7XG5cdCAgICAgICAgICAgIHZhciBkYXRhV29yZHMgPSBkYXRhLndvcmRzO1xuXG5cdCAgICAgICAgICAgIHZhciBuQml0c1RvdGFsID0gdGhpcy5fbkRhdGFCeXRlcyAqIDg7XG5cdCAgICAgICAgICAgIHZhciBuQml0c0xlZnQgPSBkYXRhLnNpZ0J5dGVzICogODtcblxuXHQgICAgICAgICAgICAvLyBBZGQgcGFkZGluZ1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbbkJpdHNMZWZ0ID4+PiA1XSB8PSAweDgwIDw8ICgyNCAtIG5CaXRzTGVmdCAlIDMyKTtcblx0ICAgICAgICAgICAgZGF0YVdvcmRzWygoKG5CaXRzTGVmdCArIDY0KSA+Pj4gOSkgPDwgNCkgKyAxNF0gPSBNYXRoLmZsb29yKG5CaXRzVG90YWwgLyAweDEwMDAwMDAwMCk7XG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1soKChuQml0c0xlZnQgKyA2NCkgPj4+IDkpIDw8IDQpICsgMTVdID0gbkJpdHNUb3RhbDtcblx0ICAgICAgICAgICAgZGF0YS5zaWdCeXRlcyA9IGRhdGFXb3Jkcy5sZW5ndGggKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIEhhc2ggZmluYWwgYmxvY2tzXG5cdCAgICAgICAgICAgIHRoaXMuX3Byb2Nlc3MoKTtcblxuXHQgICAgICAgICAgICAvLyBSZXR1cm4gZmluYWwgY29tcHV0ZWQgaGFzaFxuXHQgICAgICAgICAgICByZXR1cm4gdGhpcy5faGFzaDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgY2xvbmU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdmFyIGNsb25lID0gSGFzaGVyLmNsb25lLmNhbGwodGhpcyk7XG5cdCAgICAgICAgICAgIGNsb25lLl9oYXNoID0gdGhpcy5faGFzaC5jbG9uZSgpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBjbG9uZTtcblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgaGFzaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlNIQTI1NignbWVzc2FnZScpO1xuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBMjU2KHdvcmRBcnJheSk7XG5cdCAgICAgKi9cblx0ICAgIEMuU0hBMjU2ID0gSGFzaGVyLl9jcmVhdGVIZWxwZXIoU0hBMjU2KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgSE1BQydzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IGtleSBUaGUgc2VjcmV0IGtleS5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBITUFDLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaG1hYyA9IENyeXB0b0pTLkhtYWNTSEEyNTYobWVzc2FnZSwga2V5KTtcblx0ICAgICAqL1xuXHQgICAgQy5IbWFjU0hBMjU2ID0gSGFzaGVyLl9jcmVhdGVIbWFjSGVscGVyKFNIQTI1Nik7XG5cdH0oTWF0aCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLlNIQTI1NjtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi94NjQtY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi94NjQtY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uIChNYXRoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgSGFzaGVyID0gQ19saWIuSGFzaGVyO1xuXHQgICAgdmFyIENfeDY0ID0gQy54NjQ7XG5cdCAgICB2YXIgWDY0V29yZCA9IENfeDY0LldvcmQ7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICAvLyBDb25zdGFudHMgdGFibGVzXG5cdCAgICB2YXIgUkhPX09GRlNFVFMgPSBbXTtcblx0ICAgIHZhciBQSV9JTkRFWEVTICA9IFtdO1xuXHQgICAgdmFyIFJPVU5EX0NPTlNUQU5UUyA9IFtdO1xuXG5cdCAgICAvLyBDb21wdXRlIENvbnN0YW50c1xuXHQgICAgKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAvLyBDb21wdXRlIHJobyBvZmZzZXQgY29uc3RhbnRzXG5cdCAgICAgICAgdmFyIHggPSAxLCB5ID0gMDtcblx0ICAgICAgICBmb3IgKHZhciB0ID0gMDsgdCA8IDI0OyB0KyspIHtcblx0ICAgICAgICAgICAgUkhPX09GRlNFVFNbeCArIDUgKiB5XSA9ICgodCArIDEpICogKHQgKyAyKSAvIDIpICUgNjQ7XG5cblx0ICAgICAgICAgICAgdmFyIG5ld1ggPSB5ICUgNTtcblx0ICAgICAgICAgICAgdmFyIG5ld1kgPSAoMiAqIHggKyAzICogeSkgJSA1O1xuXHQgICAgICAgICAgICB4ID0gbmV3WDtcblx0ICAgICAgICAgICAgeSA9IG5ld1k7XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gQ29tcHV0ZSBwaSBpbmRleCBjb25zdGFudHNcblx0ICAgICAgICBmb3IgKHZhciB4ID0gMDsgeCA8IDU7IHgrKykge1xuXHQgICAgICAgICAgICBmb3IgKHZhciB5ID0gMDsgeSA8IDU7IHkrKykge1xuXHQgICAgICAgICAgICAgICAgUElfSU5ERVhFU1t4ICsgNSAqIHldID0geSArICgoMiAqIHggKyAzICogeSkgJSA1KSAqIDU7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cblx0ICAgICAgICAvLyBDb21wdXRlIHJvdW5kIGNvbnN0YW50c1xuXHQgICAgICAgIHZhciBMRlNSID0gMHgwMTtcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI0OyBpKyspIHtcblx0ICAgICAgICAgICAgdmFyIHJvdW5kQ29uc3RhbnRNc3cgPSAwO1xuXHQgICAgICAgICAgICB2YXIgcm91bmRDb25zdGFudExzdyA9IDA7XG5cblx0ICAgICAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCA3OyBqKyspIHtcblx0ICAgICAgICAgICAgICAgIGlmIChMRlNSICYgMHgwMSkge1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBiaXRQb3NpdGlvbiA9ICgxIDw8IGopIC0gMTtcblx0ICAgICAgICAgICAgICAgICAgICBpZiAoYml0UG9zaXRpb24gPCAzMikge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICByb3VuZENvbnN0YW50THN3IF49IDEgPDwgYml0UG9zaXRpb247XG5cdCAgICAgICAgICAgICAgICAgICAgfSBlbHNlIC8qIGlmIChiaXRQb3NpdGlvbiA+PSAzMikgKi8ge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICByb3VuZENvbnN0YW50TXN3IF49IDEgPDwgKGJpdFBvc2l0aW9uIC0gMzIpO1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgLy8gQ29tcHV0ZSBuZXh0IExGU1Jcblx0ICAgICAgICAgICAgICAgIGlmIChMRlNSICYgMHg4MCkge1xuXHQgICAgICAgICAgICAgICAgICAgIC8vIFByaW1pdGl2ZSBwb2x5bm9taWFsIG92ZXIgR0YoMik6IHheOCArIHheNiArIHheNSArIHheNCArIDFcblx0ICAgICAgICAgICAgICAgICAgICBMRlNSID0gKExGU1IgPDwgMSkgXiAweDcxO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgICAgICBMRlNSIDw8PSAxO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgUk9VTkRfQ09OU1RBTlRTW2ldID0gWDY0V29yZC5jcmVhdGUocm91bmRDb25zdGFudE1zdywgcm91bmRDb25zdGFudExzdyk7XG5cdCAgICAgICAgfVxuXHQgICAgfSgpKTtcblxuXHQgICAgLy8gUmV1c2FibGUgb2JqZWN0cyBmb3IgdGVtcG9yYXJ5IHZhbHVlc1xuXHQgICAgdmFyIFQgPSBbXTtcblx0ICAgIChmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNTsgaSsrKSB7XG5cdCAgICAgICAgICAgIFRbaV0gPSBYNjRXb3JkLmNyZWF0ZSgpO1xuXHQgICAgICAgIH1cblx0ICAgIH0oKSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU0hBLTMgaGFzaCBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBTSEEzID0gQ19hbGdvLlNIQTMgPSBIYXNoZXIuZXh0ZW5kKHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb25maWd1cmF0aW9uIG9wdGlvbnMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcHJvcGVydHkge251bWJlcn0gb3V0cHV0TGVuZ3RoXG5cdCAgICAgICAgICogICBUaGUgZGVzaXJlZCBudW1iZXIgb2YgYml0cyBpbiB0aGUgb3V0cHV0IGhhc2guXG5cdCAgICAgICAgICogICBPbmx5IHZhbHVlcyBwZXJtaXR0ZWQgYXJlOiAyMjQsIDI1NiwgMzg0LCA1MTIuXG5cdCAgICAgICAgICogICBEZWZhdWx0OiA1MTJcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjZmc6IEhhc2hlci5jZmcuZXh0ZW5kKHtcblx0ICAgICAgICAgICAgb3V0cHV0TGVuZ3RoOiA1MTJcblx0ICAgICAgICB9KSxcblxuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHZhciBzdGF0ZSA9IHRoaXMuX3N0YXRlID0gW11cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNTsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICBzdGF0ZVtpXSA9IG5ldyBYNjRXb3JkLmluaXQoKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHRoaXMuYmxvY2tTaXplID0gKDE2MDAgLSAyICogdGhpcy5jZmcub3V0cHV0TGVuZ3RoKSAvIDMyO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9Qcm9jZXNzQmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBzdGF0ZSA9IHRoaXMuX3N0YXRlO1xuXHQgICAgICAgICAgICB2YXIgbkJsb2NrU2l6ZUxhbmVzID0gdGhpcy5ibG9ja1NpemUgLyAyO1xuXG5cdCAgICAgICAgICAgIC8vIEFic29yYlxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IG5CbG9ja1NpemVMYW5lczsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgIHZhciBNMmkgID0gTVtvZmZzZXQgKyAyICogaV07XG5cdCAgICAgICAgICAgICAgICB2YXIgTTJpMSA9IE1bb2Zmc2V0ICsgMiAqIGkgKyAxXTtcblxuXHQgICAgICAgICAgICAgICAgLy8gU3dhcCBlbmRpYW5cblx0ICAgICAgICAgICAgICAgIE0yaSA9IChcblx0ICAgICAgICAgICAgICAgICAgICAoKChNMmkgPDwgOCkgIHwgKE0yaSA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICAgICAoKChNMmkgPDwgMjQpIHwgKE0yaSA+Pj4gOCkpICAmIDB4ZmYwMGZmMDApXG5cdCAgICAgICAgICAgICAgICApO1xuXHQgICAgICAgICAgICAgICAgTTJpMSA9IChcblx0ICAgICAgICAgICAgICAgICAgICAoKChNMmkxIDw8IDgpICB8IChNMmkxID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgICAgICgoKE0yaTEgPDwgMjQpIHwgKE0yaTEgPj4+IDgpKSAgJiAweGZmMDBmZjAwKVxuXHQgICAgICAgICAgICAgICAgKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gQWJzb3JiIG1lc3NhZ2UgaW50byBzdGF0ZVxuXHQgICAgICAgICAgICAgICAgdmFyIGxhbmUgPSBzdGF0ZVtpXTtcblx0ICAgICAgICAgICAgICAgIGxhbmUuaGlnaCBePSBNMmkxO1xuXHQgICAgICAgICAgICAgICAgbGFuZS5sb3cgIF49IE0yaTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFJvdW5kc1xuXHQgICAgICAgICAgICBmb3IgKHZhciByb3VuZCA9IDA7IHJvdW5kIDwgMjQ7IHJvdW5kKyspIHtcblx0ICAgICAgICAgICAgICAgIC8vIFRoZXRhXG5cdCAgICAgICAgICAgICAgICBmb3IgKHZhciB4ID0gMDsgeCA8IDU7IHgrKykge1xuXHQgICAgICAgICAgICAgICAgICAgIC8vIE1peCBjb2x1bW4gbGFuZXNcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgdE1zdyA9IDAsIHRMc3cgPSAwO1xuXHQgICAgICAgICAgICAgICAgICAgIGZvciAodmFyIHkgPSAwOyB5IDwgNTsgeSsrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHZhciBsYW5lID0gc3RhdGVbeCArIDUgKiB5XTtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdE1zdyBePSBsYW5lLmhpZ2g7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHRMc3cgXj0gbGFuZS5sb3c7XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAgICAgLy8gVGVtcG9yYXJ5IHZhbHVlc1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBUeCA9IFRbeF07XG5cdCAgICAgICAgICAgICAgICAgICAgVHguaGlnaCA9IHRNc3c7XG5cdCAgICAgICAgICAgICAgICAgICAgVHgubG93ICA9IHRMc3c7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgICAgICBmb3IgKHZhciB4ID0gMDsgeCA8IDU7IHgrKykge1xuXHQgICAgICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBUeDQgPSBUWyh4ICsgNCkgJSA1XTtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgVHgxID0gVFsoeCArIDEpICUgNV07XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFR4MU1zdyA9IFR4MS5oaWdoO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBUeDFMc3cgPSBUeDEubG93O1xuXG5cdCAgICAgICAgICAgICAgICAgICAgLy8gTWl4IHN1cnJvdW5kaW5nIGNvbHVtbnNcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgdE1zdyA9IFR4NC5oaWdoIF4gKChUeDFNc3cgPDwgMSkgfCAoVHgxTHN3ID4+PiAzMSkpO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciB0THN3ID0gVHg0LmxvdyAgXiAoKFR4MUxzdyA8PCAxKSB8IChUeDFNc3cgPj4+IDMxKSk7XG5cdCAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgeSA9IDA7IHkgPCA1OyB5KyspIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhbmUgPSBzdGF0ZVt4ICsgNSAqIHldO1xuXHQgICAgICAgICAgICAgICAgICAgICAgICBsYW5lLmhpZ2ggXj0gdE1zdztcblx0ICAgICAgICAgICAgICAgICAgICAgICAgbGFuZS5sb3cgIF49IHRMc3c7XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAvLyBSaG8gUGlcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIGxhbmVJbmRleCA9IDE7IGxhbmVJbmRleCA8IDI1OyBsYW5lSW5kZXgrKykge1xuXHQgICAgICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBsYW5lID0gc3RhdGVbbGFuZUluZGV4XTtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgbGFuZU1zdyA9IGxhbmUuaGlnaDtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgbGFuZUxzdyA9IGxhbmUubG93O1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciByaG9PZmZzZXQgPSBSSE9fT0ZGU0VUU1tsYW5lSW5kZXhdO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgLy8gUm90YXRlIGxhbmVzXG5cdCAgICAgICAgICAgICAgICAgICAgaWYgKHJob09mZnNldCA8IDMyKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0TXN3ID0gKGxhbmVNc3cgPDwgcmhvT2Zmc2V0KSB8IChsYW5lTHN3ID4+PiAoMzIgLSByaG9PZmZzZXQpKTtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdmFyIHRMc3cgPSAobGFuZUxzdyA8PCByaG9PZmZzZXQpIHwgKGxhbmVNc3cgPj4+ICgzMiAtIHJob09mZnNldCkpO1xuXHQgICAgICAgICAgICAgICAgICAgIH0gZWxzZSAvKiBpZiAocmhvT2Zmc2V0ID49IDMyKSAqLyB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0TXN3ID0gKGxhbmVMc3cgPDwgKHJob09mZnNldCAtIDMyKSkgfCAobGFuZU1zdyA+Pj4gKDY0IC0gcmhvT2Zmc2V0KSk7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0THN3ID0gKGxhbmVNc3cgPDwgKHJob09mZnNldCAtIDMyKSkgfCAobGFuZUxzdyA+Pj4gKDY0IC0gcmhvT2Zmc2V0KSk7XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAgICAgLy8gVHJhbnNwb3NlIGxhbmVzXG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFRQaUxhbmUgPSBUW1BJX0lOREVYRVNbbGFuZUluZGV4XV07XG5cdCAgICAgICAgICAgICAgICAgICAgVFBpTGFuZS5oaWdoID0gdE1zdztcblx0ICAgICAgICAgICAgICAgICAgICBUUGlMYW5lLmxvdyAgPSB0THN3O1xuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAvLyBSaG8gcGkgYXQgeCA9IHkgPSAwXG5cdCAgICAgICAgICAgICAgICB2YXIgVDAgPSBUWzBdO1xuXHQgICAgICAgICAgICAgICAgdmFyIHN0YXRlMCA9IHN0YXRlWzBdO1xuXHQgICAgICAgICAgICAgICAgVDAuaGlnaCA9IHN0YXRlMC5oaWdoO1xuXHQgICAgICAgICAgICAgICAgVDAubG93ICA9IHN0YXRlMC5sb3c7XG5cblx0ICAgICAgICAgICAgICAgIC8vIENoaVxuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgeCA9IDA7IHggPCA1OyB4KyspIHtcblx0ICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciB5ID0gMDsgeSA8IDU7IHkrKykge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhbmVJbmRleCA9IHggKyA1ICogeTtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdmFyIGxhbmUgPSBzdGF0ZVtsYW5lSW5kZXhdO1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB2YXIgVExhbmUgPSBUW2xhbmVJbmRleF07XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHZhciBUeDFMYW5lID0gVFsoKHggKyAxKSAlIDUpICsgNSAqIHldO1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB2YXIgVHgyTGFuZSA9IFRbKCh4ICsgMikgJSA1KSArIDUgKiB5XTtcblxuXHQgICAgICAgICAgICAgICAgICAgICAgICAvLyBNaXggcm93c1xuXHQgICAgICAgICAgICAgICAgICAgICAgICBsYW5lLmhpZ2ggPSBUTGFuZS5oaWdoIF4gKH5UeDFMYW5lLmhpZ2ggJiBUeDJMYW5lLmhpZ2gpO1xuXHQgICAgICAgICAgICAgICAgICAgICAgICBsYW5lLmxvdyAgPSBUTGFuZS5sb3cgIF4gKH5UeDFMYW5lLmxvdyAgJiBUeDJMYW5lLmxvdyk7XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAvLyBJb3RhXG5cdCAgICAgICAgICAgICAgICB2YXIgbGFuZSA9IHN0YXRlWzBdO1xuXHQgICAgICAgICAgICAgICAgdmFyIHJvdW5kQ29uc3RhbnQgPSBST1VORF9DT05TVEFOVFNbcm91bmRdO1xuXHQgICAgICAgICAgICAgICAgbGFuZS5oaWdoIF49IHJvdW5kQ29uc3RhbnQuaGlnaDtcblx0ICAgICAgICAgICAgICAgIGxhbmUubG93ICBePSByb3VuZENvbnN0YW50Lmxvdzs7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvRmluYWxpemU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkYXRhID0gdGhpcy5fZGF0YTtcblx0ICAgICAgICAgICAgdmFyIGRhdGFXb3JkcyA9IGRhdGEud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBuQml0c1RvdGFsID0gdGhpcy5fbkRhdGFCeXRlcyAqIDg7XG5cdCAgICAgICAgICAgIHZhciBuQml0c0xlZnQgPSBkYXRhLnNpZ0J5dGVzICogODtcblx0ICAgICAgICAgICAgdmFyIGJsb2NrU2l6ZUJpdHMgPSB0aGlzLmJsb2NrU2l6ZSAqIDMyO1xuXG5cdCAgICAgICAgICAgIC8vIEFkZCBwYWRkaW5nXG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1tuQml0c0xlZnQgPj4+IDVdIHw9IDB4MSA8PCAoMjQgLSBuQml0c0xlZnQgJSAzMik7XG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1soKE1hdGguY2VpbCgobkJpdHNMZWZ0ICsgMSkgLyBibG9ja1NpemVCaXRzKSAqIGJsb2NrU2l6ZUJpdHMpID4+PiA1KSAtIDFdIHw9IDB4ODA7XG5cdCAgICAgICAgICAgIGRhdGEuc2lnQnl0ZXMgPSBkYXRhV29yZHMubGVuZ3RoICogNDtcblxuXHQgICAgICAgICAgICAvLyBIYXNoIGZpbmFsIGJsb2Nrc1xuXHQgICAgICAgICAgICB0aGlzLl9wcm9jZXNzKCk7XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBzdGF0ZSA9IHRoaXMuX3N0YXRlO1xuXHQgICAgICAgICAgICB2YXIgb3V0cHV0TGVuZ3RoQnl0ZXMgPSB0aGlzLmNmZy5vdXRwdXRMZW5ndGggLyA4O1xuXHQgICAgICAgICAgICB2YXIgb3V0cHV0TGVuZ3RoTGFuZXMgPSBvdXRwdXRMZW5ndGhCeXRlcyAvIDg7XG5cblx0ICAgICAgICAgICAgLy8gU3F1ZWV6ZVxuXHQgICAgICAgICAgICB2YXIgaGFzaFdvcmRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgb3V0cHV0TGVuZ3RoTGFuZXM7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgICAgICB2YXIgbGFuZSA9IHN0YXRlW2ldO1xuXHQgICAgICAgICAgICAgICAgdmFyIGxhbmVNc3cgPSBsYW5lLmhpZ2g7XG5cdCAgICAgICAgICAgICAgICB2YXIgbGFuZUxzdyA9IGxhbmUubG93O1xuXG5cdCAgICAgICAgICAgICAgICAvLyBTd2FwIGVuZGlhblxuXHQgICAgICAgICAgICAgICAgbGFuZU1zdyA9IChcblx0ICAgICAgICAgICAgICAgICAgICAoKChsYW5lTXN3IDw8IDgpICB8IChsYW5lTXN3ID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgICAgICgoKGxhbmVNc3cgPDwgMjQpIHwgKGxhbmVNc3cgPj4+IDgpKSAgJiAweGZmMDBmZjAwKVxuXHQgICAgICAgICAgICAgICAgKTtcblx0ICAgICAgICAgICAgICAgIGxhbmVMc3cgPSAoXG5cdCAgICAgICAgICAgICAgICAgICAgKCgobGFuZUxzdyA8PCA4KSAgfCAobGFuZUxzdyA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICAgICAoKChsYW5lTHN3IDw8IDI0KSB8IChsYW5lTHN3ID4+PiA4KSkgICYgMHhmZjAwZmYwMClcblx0ICAgICAgICAgICAgICAgICk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFNxdWVlemUgc3RhdGUgdG8gcmV0cmlldmUgaGFzaFxuXHQgICAgICAgICAgICAgICAgaGFzaFdvcmRzLnB1c2gobGFuZUxzdyk7XG5cdCAgICAgICAgICAgICAgICBoYXNoV29yZHMucHVzaChsYW5lTXN3KTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFJldHVybiBmaW5hbCBjb21wdXRlZCBoYXNoXG5cdCAgICAgICAgICAgIHJldHVybiBuZXcgV29yZEFycmF5LmluaXQoaGFzaFdvcmRzLCBvdXRwdXRMZW5ndGhCeXRlcyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGNsb25lOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHZhciBjbG9uZSA9IEhhc2hlci5jbG9uZS5jYWxsKHRoaXMpO1xuXG5cdCAgICAgICAgICAgIHZhciBzdGF0ZSA9IGNsb25lLl9zdGF0ZSA9IHRoaXMuX3N0YXRlLnNsaWNlKDApO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI1OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHN0YXRlW2ldID0gc3RhdGVbaV0uY2xvbmUoKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBjbG9uZTtcblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgaGFzaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlNIQTMoJ21lc3NhZ2UnKTtcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlNIQTMod29yZEFycmF5KTtcblx0ICAgICAqL1xuXHQgICAgQy5TSEEzID0gSGFzaGVyLl9jcmVhdGVIZWxwZXIoU0hBMyk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIEhNQUMncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBrZXkgVGhlIHNlY3JldCBrZXkuXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgSE1BQy5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhtYWMgPSBDcnlwdG9KUy5IbWFjU0hBMyhtZXNzYWdlLCBrZXkpO1xuXHQgICAgICovXG5cdCAgICBDLkhtYWNTSEEzID0gSGFzaGVyLl9jcmVhdGVIbWFjSGVscGVyKFNIQTMpO1xuXHR9KE1hdGgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5TSEEzO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL3g2NC1jb3JlXCIpLCByZXF1aXJlKFwiLi9zaGE1MTJcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4veDY0LWNvcmVcIiwgXCIuL3NoYTUxMlwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uICgpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX3g2NCA9IEMueDY0O1xuXHQgICAgdmFyIFg2NFdvcmQgPSBDX3g2NC5Xb3JkO1xuXHQgICAgdmFyIFg2NFdvcmRBcnJheSA9IENfeDY0LldvcmRBcnJheTtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cdCAgICB2YXIgU0hBNTEyID0gQ19hbGdvLlNIQTUxMjtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTSEEtMzg0IGhhc2ggYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgU0hBMzg0ID0gQ19hbGdvLlNIQTM4NCA9IFNIQTUxMi5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHRoaXMuX2hhc2ggPSBuZXcgWDY0V29yZEFycmF5LmluaXQoW1xuXHQgICAgICAgICAgICAgICAgbmV3IFg2NFdvcmQuaW5pdCgweGNiYmI5ZDVkLCAweGMxMDU5ZWQ4KSwgbmV3IFg2NFdvcmQuaW5pdCgweDYyOWEyOTJhLCAweDM2N2NkNTA3KSxcblx0ICAgICAgICAgICAgICAgIG5ldyBYNjRXb3JkLmluaXQoMHg5MTU5MDE1YSwgMHgzMDcwZGQxNyksIG5ldyBYNjRXb3JkLmluaXQoMHgxNTJmZWNkOCwgMHhmNzBlNTkzOSksXG5cdCAgICAgICAgICAgICAgICBuZXcgWDY0V29yZC5pbml0KDB4NjczMzI2NjcsIDB4ZmZjMDBiMzEpLCBuZXcgWDY0V29yZC5pbml0KDB4OGViNDRhODcsIDB4Njg1ODE1MTEpLFxuXHQgICAgICAgICAgICAgICAgbmV3IFg2NFdvcmQuaW5pdCgweGRiMGMyZTBkLCAweDY0Zjk4ZmE3KSwgbmV3IFg2NFdvcmQuaW5pdCgweDQ3YjU0ODFkLCAweGJlZmE0ZmE0KVxuXHQgICAgICAgICAgICBdKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvRmluYWxpemU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdmFyIGhhc2ggPSBTSEE1MTIuX2RvRmluYWxpemUuY2FsbCh0aGlzKTtcblxuXHQgICAgICAgICAgICBoYXNoLnNpZ0J5dGVzIC09IDE2O1xuXG5cdCAgICAgICAgICAgIHJldHVybiBoYXNoO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBoYXNoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBMzg0KCdtZXNzYWdlJyk7XG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5TSEEzODQod29yZEFycmF5KTtcblx0ICAgICAqL1xuXHQgICAgQy5TSEEzODQgPSBTSEE1MTIuX2NyZWF0ZUhlbHBlcihTSEEzODQpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBITUFDJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30ga2V5IFRoZSBzZWNyZXQga2V5LlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIEhNQUMuXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBobWFjID0gQ3J5cHRvSlMuSG1hY1NIQTM4NChtZXNzYWdlLCBrZXkpO1xuXHQgICAgICovXG5cdCAgICBDLkhtYWNTSEEzODQgPSBTSEE1MTIuX2NyZWF0ZUhtYWNIZWxwZXIoU0hBMzg0KTtcblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5TSEEzODQ7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4veDY0LWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4veDY0LWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBIYXNoZXIgPSBDX2xpYi5IYXNoZXI7XG5cdCAgICB2YXIgQ194NjQgPSBDLng2NDtcblx0ICAgIHZhciBYNjRXb3JkID0gQ194NjQuV29yZDtcblx0ICAgIHZhciBYNjRXb3JkQXJyYXkgPSBDX3g2NC5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICBmdW5jdGlvbiBYNjRXb3JkX2NyZWF0ZSgpIHtcblx0ICAgICAgICByZXR1cm4gWDY0V29yZC5jcmVhdGUuYXBwbHkoWDY0V29yZCwgYXJndW1lbnRzKTtcblx0ICAgIH1cblxuXHQgICAgLy8gQ29uc3RhbnRzXG5cdCAgICB2YXIgSyA9IFtcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDQyOGEyZjk4LCAweGQ3MjhhZTIyKSwgWDY0V29yZF9jcmVhdGUoMHg3MTM3NDQ5MSwgMHgyM2VmNjVjZCksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHhiNWMwZmJjZiwgMHhlYzRkM2IyZiksIFg2NFdvcmRfY3JlYXRlKDB4ZTliNWRiYTUsIDB4ODE4OWRiYmMpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4Mzk1NmMyNWIsIDB4ZjM0OGI1MzgpLCBYNjRXb3JkX2NyZWF0ZSgweDU5ZjExMWYxLCAweGI2MDVkMDE5KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDkyM2Y4MmE0LCAweGFmMTk0ZjliKSwgWDY0V29yZF9jcmVhdGUoMHhhYjFjNWVkNSwgMHhkYTZkODExOCksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHhkODA3YWE5OCwgMHhhMzAzMDI0MiksIFg2NFdvcmRfY3JlYXRlKDB4MTI4MzViMDEsIDB4NDU3MDZmYmUpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4MjQzMTg1YmUsIDB4NGVlNGIyOGMpLCBYNjRXb3JkX2NyZWF0ZSgweDU1MGM3ZGMzLCAweGQ1ZmZiNGUyKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDcyYmU1ZDc0LCAweGYyN2I4OTZmKSwgWDY0V29yZF9jcmVhdGUoMHg4MGRlYjFmZSwgMHgzYjE2OTZiMSksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg5YmRjMDZhNywgMHgyNWM3MTIzNSksIFg2NFdvcmRfY3JlYXRlKDB4YzE5YmYxNzQsIDB4Y2Y2OTI2OTQpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4ZTQ5YjY5YzEsIDB4OWVmMTRhZDIpLCBYNjRXb3JkX2NyZWF0ZSgweGVmYmU0Nzg2LCAweDM4NGYyNWUzKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDBmYzE5ZGM2LCAweDhiOGNkNWI1KSwgWDY0V29yZF9jcmVhdGUoMHgyNDBjYTFjYywgMHg3N2FjOWM2NSksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHgyZGU5MmM2ZiwgMHg1OTJiMDI3NSksIFg2NFdvcmRfY3JlYXRlKDB4NGE3NDg0YWEsIDB4NmVhNmU0ODMpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4NWNiMGE5ZGMsIDB4YmQ0MWZiZDQpLCBYNjRXb3JkX2NyZWF0ZSgweDc2Zjk4OGRhLCAweDgzMTE1M2I1KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDk4M2U1MTUyLCAweGVlNjZkZmFiKSwgWDY0V29yZF9jcmVhdGUoMHhhODMxYzY2ZCwgMHgyZGI0MzIxMCksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHhiMDAzMjdjOCwgMHg5OGZiMjEzZiksIFg2NFdvcmRfY3JlYXRlKDB4YmY1OTdmYzcsIDB4YmVlZjBlZTQpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4YzZlMDBiZjMsIDB4M2RhODhmYzIpLCBYNjRXb3JkX2NyZWF0ZSgweGQ1YTc5MTQ3LCAweDkzMGFhNzI1KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDA2Y2E2MzUxLCAweGUwMDM4MjZmKSwgWDY0V29yZF9jcmVhdGUoMHgxNDI5Mjk2NywgMHgwYTBlNmU3MCksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHgyN2I3MGE4NSwgMHg0NmQyMmZmYyksIFg2NFdvcmRfY3JlYXRlKDB4MmUxYjIxMzgsIDB4NWMyNmM5MjYpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4NGQyYzZkZmMsIDB4NWFjNDJhZWQpLCBYNjRXb3JkX2NyZWF0ZSgweDUzMzgwZDEzLCAweDlkOTViM2RmKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDY1MGE3MzU0LCAweDhiYWY2M2RlKSwgWDY0V29yZF9jcmVhdGUoMHg3NjZhMGFiYiwgMHgzYzc3YjJhOCksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg4MWMyYzkyZSwgMHg0N2VkYWVlNiksIFg2NFdvcmRfY3JlYXRlKDB4OTI3MjJjODUsIDB4MTQ4MjM1M2IpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4YTJiZmU4YTEsIDB4NGNmMTAzNjQpLCBYNjRXb3JkX2NyZWF0ZSgweGE4MWE2NjRiLCAweGJjNDIzMDAxKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweGMyNGI4YjcwLCAweGQwZjg5NzkxKSwgWDY0V29yZF9jcmVhdGUoMHhjNzZjNTFhMywgMHgwNjU0YmUzMCksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHhkMTkyZTgxOSwgMHhkNmVmNTIxOCksIFg2NFdvcmRfY3JlYXRlKDB4ZDY5OTA2MjQsIDB4NTU2NWE5MTApLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4ZjQwZTM1ODUsIDB4NTc3MTIwMmEpLCBYNjRXb3JkX2NyZWF0ZSgweDEwNmFhMDcwLCAweDMyYmJkMWI4KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDE5YTRjMTE2LCAweGI4ZDJkMGM4KSwgWDY0V29yZF9jcmVhdGUoMHgxZTM3NmMwOCwgMHg1MTQxYWI1MyksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHgyNzQ4Nzc0YywgMHhkZjhlZWI5OSksIFg2NFdvcmRfY3JlYXRlKDB4MzRiMGJjYjUsIDB4ZTE5YjQ4YTgpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4MzkxYzBjYjMsIDB4YzVjOTVhNjMpLCBYNjRXb3JkX2NyZWF0ZSgweDRlZDhhYTRhLCAweGUzNDE4YWNiKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDViOWNjYTRmLCAweDc3NjNlMzczKSwgWDY0V29yZF9jcmVhdGUoMHg2ODJlNmZmMywgMHhkNmIyYjhhMyksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg3NDhmODJlZSwgMHg1ZGVmYjJmYyksIFg2NFdvcmRfY3JlYXRlKDB4NzhhNTYzNmYsIDB4NDMxNzJmNjApLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4ODRjODc4MTQsIDB4YTFmMGFiNzIpLCBYNjRXb3JkX2NyZWF0ZSgweDhjYzcwMjA4LCAweDFhNjQzOWVjKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDkwYmVmZmZhLCAweDIzNjMxZTI4KSwgWDY0V29yZF9jcmVhdGUoMHhhNDUwNmNlYiwgMHhkZTgyYmRlOSksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHhiZWY5YTNmNywgMHhiMmM2NzkxNSksIFg2NFdvcmRfY3JlYXRlKDB4YzY3MTc4ZjIsIDB4ZTM3MjUzMmIpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4Y2EyNzNlY2UsIDB4ZWEyNjYxOWMpLCBYNjRXb3JkX2NyZWF0ZSgweGQxODZiOGM3LCAweDIxYzBjMjA3KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweGVhZGE3ZGQ2LCAweGNkZTBlYjFlKSwgWDY0V29yZF9jcmVhdGUoMHhmNTdkNGY3ZiwgMHhlZTZlZDE3OCksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHgwNmYwNjdhYSwgMHg3MjE3NmZiYSksIFg2NFdvcmRfY3JlYXRlKDB4MGE2MzdkYzUsIDB4YTJjODk4YTYpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4MTEzZjk4MDQsIDB4YmVmOTBkYWUpLCBYNjRXb3JkX2NyZWF0ZSgweDFiNzEwYjM1LCAweDEzMWM0NzFiKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDI4ZGI3N2Y1LCAweDIzMDQ3ZDg0KSwgWDY0V29yZF9jcmVhdGUoMHgzMmNhYWI3YiwgMHg0MGM3MjQ5MyksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHgzYzllYmUwYSwgMHgxNWM5YmViYyksIFg2NFdvcmRfY3JlYXRlKDB4NDMxZDY3YzQsIDB4OWMxMDBkNGMpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4NGNjNWQ0YmUsIDB4Y2IzZTQyYjYpLCBYNjRXb3JkX2NyZWF0ZSgweDU5N2YyOTljLCAweGZjNjU3ZTJhKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDVmY2I2ZmFiLCAweDNhZDZmYWVjKSwgWDY0V29yZF9jcmVhdGUoMHg2YzQ0MTk4YywgMHg0YTQ3NTgxNylcblx0ICAgIF07XG5cblx0ICAgIC8vIFJldXNhYmxlIG9iamVjdHNcblx0ICAgIHZhciBXID0gW107XG5cdCAgICAoZnVuY3Rpb24gKCkge1xuXHQgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgODA7IGkrKykge1xuXHQgICAgICAgICAgICBXW2ldID0gWDY0V29yZF9jcmVhdGUoKTtcblx0ICAgICAgICB9XG5cdCAgICB9KCkpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNIQS01MTIgaGFzaCBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBTSEE1MTIgPSBDX2FsZ28uU0hBNTEyID0gSGFzaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgX2RvUmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdGhpcy5faGFzaCA9IG5ldyBYNjRXb3JkQXJyYXkuaW5pdChbXG5cdCAgICAgICAgICAgICAgICBuZXcgWDY0V29yZC5pbml0KDB4NmEwOWU2NjcsIDB4ZjNiY2M5MDgpLCBuZXcgWDY0V29yZC5pbml0KDB4YmI2N2FlODUsIDB4ODRjYWE3M2IpLFxuXHQgICAgICAgICAgICAgICAgbmV3IFg2NFdvcmQuaW5pdCgweDNjNmVmMzcyLCAweGZlOTRmODJiKSwgbmV3IFg2NFdvcmQuaW5pdCgweGE1NGZmNTNhLCAweDVmMWQzNmYxKSxcblx0ICAgICAgICAgICAgICAgIG5ldyBYNjRXb3JkLmluaXQoMHg1MTBlNTI3ZiwgMHhhZGU2ODJkMSksIG5ldyBYNjRXb3JkLmluaXQoMHg5YjA1Njg4YywgMHgyYjNlNmMxZiksXG5cdCAgICAgICAgICAgICAgICBuZXcgWDY0V29yZC5pbml0KDB4MWY4M2Q5YWIsIDB4ZmI0MWJkNmIpLCBuZXcgWDY0V29yZC5pbml0KDB4NWJlMGNkMTksIDB4MTM3ZTIxNzkpXG5cdCAgICAgICAgICAgIF0pO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9Qcm9jZXNzQmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBIID0gdGhpcy5faGFzaC53b3JkcztcblxuXHQgICAgICAgICAgICB2YXIgSDAgPSBIWzBdO1xuXHQgICAgICAgICAgICB2YXIgSDEgPSBIWzFdO1xuXHQgICAgICAgICAgICB2YXIgSDIgPSBIWzJdO1xuXHQgICAgICAgICAgICB2YXIgSDMgPSBIWzNdO1xuXHQgICAgICAgICAgICB2YXIgSDQgPSBIWzRdO1xuXHQgICAgICAgICAgICB2YXIgSDUgPSBIWzVdO1xuXHQgICAgICAgICAgICB2YXIgSDYgPSBIWzZdO1xuXHQgICAgICAgICAgICB2YXIgSDcgPSBIWzddO1xuXG5cdCAgICAgICAgICAgIHZhciBIMGggPSBIMC5oaWdoO1xuXHQgICAgICAgICAgICB2YXIgSDBsID0gSDAubG93O1xuXHQgICAgICAgICAgICB2YXIgSDFoID0gSDEuaGlnaDtcblx0ICAgICAgICAgICAgdmFyIEgxbCA9IEgxLmxvdztcblx0ICAgICAgICAgICAgdmFyIEgyaCA9IEgyLmhpZ2g7XG5cdCAgICAgICAgICAgIHZhciBIMmwgPSBIMi5sb3c7XG5cdCAgICAgICAgICAgIHZhciBIM2ggPSBIMy5oaWdoO1xuXHQgICAgICAgICAgICB2YXIgSDNsID0gSDMubG93O1xuXHQgICAgICAgICAgICB2YXIgSDRoID0gSDQuaGlnaDtcblx0ICAgICAgICAgICAgdmFyIEg0bCA9IEg0Lmxvdztcblx0ICAgICAgICAgICAgdmFyIEg1aCA9IEg1LmhpZ2g7XG5cdCAgICAgICAgICAgIHZhciBINWwgPSBINS5sb3c7XG5cdCAgICAgICAgICAgIHZhciBINmggPSBINi5oaWdoO1xuXHQgICAgICAgICAgICB2YXIgSDZsID0gSDYubG93O1xuXHQgICAgICAgICAgICB2YXIgSDdoID0gSDcuaGlnaDtcblx0ICAgICAgICAgICAgdmFyIEg3bCA9IEg3LmxvdztcblxuXHQgICAgICAgICAgICAvLyBXb3JraW5nIHZhcmlhYmxlc1xuXHQgICAgICAgICAgICB2YXIgYWggPSBIMGg7XG5cdCAgICAgICAgICAgIHZhciBhbCA9IEgwbDtcblx0ICAgICAgICAgICAgdmFyIGJoID0gSDFoO1xuXHQgICAgICAgICAgICB2YXIgYmwgPSBIMWw7XG5cdCAgICAgICAgICAgIHZhciBjaCA9IEgyaDtcblx0ICAgICAgICAgICAgdmFyIGNsID0gSDJsO1xuXHQgICAgICAgICAgICB2YXIgZGggPSBIM2g7XG5cdCAgICAgICAgICAgIHZhciBkbCA9IEgzbDtcblx0ICAgICAgICAgICAgdmFyIGVoID0gSDRoO1xuXHQgICAgICAgICAgICB2YXIgZWwgPSBINGw7XG5cdCAgICAgICAgICAgIHZhciBmaCA9IEg1aDtcblx0ICAgICAgICAgICAgdmFyIGZsID0gSDVsO1xuXHQgICAgICAgICAgICB2YXIgZ2ggPSBINmg7XG5cdCAgICAgICAgICAgIHZhciBnbCA9IEg2bDtcblx0ICAgICAgICAgICAgdmFyIGhoID0gSDdoO1xuXHQgICAgICAgICAgICB2YXIgaGwgPSBIN2w7XG5cblx0ICAgICAgICAgICAgLy8gUm91bmRzXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgODA7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgICAgIHZhciBXaSA9IFdbaV07XG5cblx0ICAgICAgICAgICAgICAgIC8vIEV4dGVuZCBtZXNzYWdlXG5cdCAgICAgICAgICAgICAgICBpZiAoaSA8IDE2KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpaCA9IFdpLmhpZ2ggPSBNW29mZnNldCArIGkgKiAyXSAgICAgfCAwO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBXaWwgPSBXaS5sb3cgID0gTVtvZmZzZXQgKyBpICogMiArIDFdIHwgMDtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICAgICAgLy8gR2FtbWEwXG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMHggID0gV1tpIC0gMTVdO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTB4aCA9IGdhbW1hMHguaGlnaDtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgZ2FtbWEweGwgPSBnYW1tYTB4Lmxvdztcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgZ2FtbWEwaCAgPSAoKGdhbW1hMHhoID4+PiAxKSB8IChnYW1tYTB4bCA8PCAzMSkpIF4gKChnYW1tYTB4aCA+Pj4gOCkgfCAoZ2FtbWEweGwgPDwgMjQpKSBeIChnYW1tYTB4aCA+Pj4gNyk7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMGwgID0gKChnYW1tYTB4bCA+Pj4gMSkgfCAoZ2FtbWEweGggPDwgMzEpKSBeICgoZ2FtbWEweGwgPj4+IDgpIHwgKGdhbW1hMHhoIDw8IDI0KSkgXiAoKGdhbW1hMHhsID4+PiA3KSB8IChnYW1tYTB4aCA8PCAyNSkpO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgLy8gR2FtbWExXG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMXggID0gV1tpIC0gMl07XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMXhoID0gZ2FtbWExeC5oaWdoO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTF4bCA9IGdhbW1hMXgubG93O1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTFoICA9ICgoZ2FtbWExeGggPj4+IDE5KSB8IChnYW1tYTF4bCA8PCAxMykpIF4gKChnYW1tYTF4aCA8PCAzKSB8IChnYW1tYTF4bCA+Pj4gMjkpKSBeIChnYW1tYTF4aCA+Pj4gNik7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMWwgID0gKChnYW1tYTF4bCA+Pj4gMTkpIHwgKGdhbW1hMXhoIDw8IDEzKSkgXiAoKGdhbW1hMXhsIDw8IDMpIHwgKGdhbW1hMXhoID4+PiAyOSkpIF4gKChnYW1tYTF4bCA+Pj4gNikgfCAoZ2FtbWExeGggPDwgMjYpKTtcblxuXHQgICAgICAgICAgICAgICAgICAgIC8vIFdbaV0gPSBnYW1tYTAgKyBXW2kgLSA3XSArIGdhbW1hMSArIFdbaSAtIDE2XVxuXHQgICAgICAgICAgICAgICAgICAgIHZhciBXaTcgID0gV1tpIC0gN107XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpN2ggPSBXaTcuaGlnaDtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgV2k3bCA9IFdpNy5sb3c7XG5cblx0ICAgICAgICAgICAgICAgICAgICB2YXIgV2kxNiAgPSBXW2kgLSAxNl07XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpMTZoID0gV2kxNi5oaWdoO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBXaTE2bCA9IFdpMTYubG93O1xuXG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpbCA9IGdhbW1hMGwgKyBXaTdsO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBXaWggPSBnYW1tYTBoICsgV2k3aCArICgoV2lsID4+PiAwKSA8IChnYW1tYTBsID4+PiAwKSA/IDEgOiAwKTtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgV2lsID0gV2lsICsgZ2FtbWExbDtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgV2loID0gV2loICsgZ2FtbWExaCArICgoV2lsID4+PiAwKSA8IChnYW1tYTFsID4+PiAwKSA/IDEgOiAwKTtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgV2lsID0gV2lsICsgV2kxNmw7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpaCA9IFdpaCArIFdpMTZoICsgKChXaWwgPj4+IDApIDwgKFdpMTZsID4+PiAwKSA/IDEgOiAwKTtcblxuXHQgICAgICAgICAgICAgICAgICAgIFdpLmhpZ2ggPSBXaWg7XG5cdCAgICAgICAgICAgICAgICAgICAgV2kubG93ICA9IFdpbDtcblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgdmFyIGNoaCAgPSAoZWggJiBmaCkgXiAofmVoICYgZ2gpO1xuXHQgICAgICAgICAgICAgICAgdmFyIGNobCAgPSAoZWwgJiBmbCkgXiAofmVsICYgZ2wpO1xuXHQgICAgICAgICAgICAgICAgdmFyIG1hamggPSAoYWggJiBiaCkgXiAoYWggJiBjaCkgXiAoYmggJiBjaCk7XG5cdCAgICAgICAgICAgICAgICB2YXIgbWFqbCA9IChhbCAmIGJsKSBeIChhbCAmIGNsKSBeIChibCAmIGNsKTtcblxuXHQgICAgICAgICAgICAgICAgdmFyIHNpZ21hMGggPSAoKGFoID4+PiAyOCkgfCAoYWwgPDwgNCkpICBeICgoYWggPDwgMzApICB8IChhbCA+Pj4gMikpIF4gKChhaCA8PCAyNSkgfCAoYWwgPj4+IDcpKTtcblx0ICAgICAgICAgICAgICAgIHZhciBzaWdtYTBsID0gKChhbCA+Pj4gMjgpIHwgKGFoIDw8IDQpKSAgXiAoKGFsIDw8IDMwKSAgfCAoYWggPj4+IDIpKSBeICgoYWwgPDwgMjUpIHwgKGFoID4+PiA3KSk7XG5cdCAgICAgICAgICAgICAgICB2YXIgc2lnbWExaCA9ICgoZWggPj4+IDE0KSB8IChlbCA8PCAxOCkpIF4gKChlaCA+Pj4gMTgpIHwgKGVsIDw8IDE0KSkgXiAoKGVoIDw8IDIzKSB8IChlbCA+Pj4gOSkpO1xuXHQgICAgICAgICAgICAgICAgdmFyIHNpZ21hMWwgPSAoKGVsID4+PiAxNCkgfCAoZWggPDwgMTgpKSBeICgoZWwgPj4+IDE4KSB8IChlaCA8PCAxNCkpIF4gKChlbCA8PCAyMykgfCAoZWggPj4+IDkpKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gdDEgPSBoICsgc2lnbWExICsgY2ggKyBLW2ldICsgV1tpXVxuXHQgICAgICAgICAgICAgICAgdmFyIEtpICA9IEtbaV07XG5cdCAgICAgICAgICAgICAgICB2YXIgS2loID0gS2kuaGlnaDtcblx0ICAgICAgICAgICAgICAgIHZhciBLaWwgPSBLaS5sb3c7XG5cblx0ICAgICAgICAgICAgICAgIHZhciB0MWwgPSBobCArIHNpZ21hMWw7XG5cdCAgICAgICAgICAgICAgICB2YXIgdDFoID0gaGggKyBzaWdtYTFoICsgKCh0MWwgPj4+IDApIDwgKGhsID4+PiAwKSA/IDEgOiAwKTtcblx0ICAgICAgICAgICAgICAgIHZhciB0MWwgPSB0MWwgKyBjaGw7XG5cdCAgICAgICAgICAgICAgICB2YXIgdDFoID0gdDFoICsgY2hoICsgKCh0MWwgPj4+IDApIDwgKGNobCA+Pj4gMCkgPyAxIDogMCk7XG5cdCAgICAgICAgICAgICAgICB2YXIgdDFsID0gdDFsICsgS2lsO1xuXHQgICAgICAgICAgICAgICAgdmFyIHQxaCA9IHQxaCArIEtpaCArICgodDFsID4+PiAwKSA8IChLaWwgPj4+IDApID8gMSA6IDApO1xuXHQgICAgICAgICAgICAgICAgdmFyIHQxbCA9IHQxbCArIFdpbDtcblx0ICAgICAgICAgICAgICAgIHZhciB0MWggPSB0MWggKyBXaWggKyAoKHQxbCA+Pj4gMCkgPCAoV2lsID4+PiAwKSA/IDEgOiAwKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gdDIgPSBzaWdtYTAgKyBtYWpcblx0ICAgICAgICAgICAgICAgIHZhciB0MmwgPSBzaWdtYTBsICsgbWFqbDtcblx0ICAgICAgICAgICAgICAgIHZhciB0MmggPSBzaWdtYTBoICsgbWFqaCArICgodDJsID4+PiAwKSA8IChzaWdtYTBsID4+PiAwKSA/IDEgOiAwKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gVXBkYXRlIHdvcmtpbmcgdmFyaWFibGVzXG5cdCAgICAgICAgICAgICAgICBoaCA9IGdoO1xuXHQgICAgICAgICAgICAgICAgaGwgPSBnbDtcblx0ICAgICAgICAgICAgICAgIGdoID0gZmg7XG5cdCAgICAgICAgICAgICAgICBnbCA9IGZsO1xuXHQgICAgICAgICAgICAgICAgZmggPSBlaDtcblx0ICAgICAgICAgICAgICAgIGZsID0gZWw7XG5cdCAgICAgICAgICAgICAgICBlbCA9IChkbCArIHQxbCkgfCAwO1xuXHQgICAgICAgICAgICAgICAgZWggPSAoZGggKyB0MWggKyAoKGVsID4+PiAwKSA8IChkbCA+Pj4gMCkgPyAxIDogMCkpIHwgMDtcblx0ICAgICAgICAgICAgICAgIGRoID0gY2g7XG5cdCAgICAgICAgICAgICAgICBkbCA9IGNsO1xuXHQgICAgICAgICAgICAgICAgY2ggPSBiaDtcblx0ICAgICAgICAgICAgICAgIGNsID0gYmw7XG5cdCAgICAgICAgICAgICAgICBiaCA9IGFoO1xuXHQgICAgICAgICAgICAgICAgYmwgPSBhbDtcblx0ICAgICAgICAgICAgICAgIGFsID0gKHQxbCArIHQybCkgfCAwO1xuXHQgICAgICAgICAgICAgICAgYWggPSAodDFoICsgdDJoICsgKChhbCA+Pj4gMCkgPCAodDFsID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gSW50ZXJtZWRpYXRlIGhhc2ggdmFsdWVcblx0ICAgICAgICAgICAgSDBsID0gSDAubG93ICA9IChIMGwgKyBhbCk7XG5cdCAgICAgICAgICAgIEgwLmhpZ2ggPSAoSDBoICsgYWggKyAoKEgwbCA+Pj4gMCkgPCAoYWwgPj4+IDApID8gMSA6IDApKTtcblx0ICAgICAgICAgICAgSDFsID0gSDEubG93ICA9IChIMWwgKyBibCk7XG5cdCAgICAgICAgICAgIEgxLmhpZ2ggPSAoSDFoICsgYmggKyAoKEgxbCA+Pj4gMCkgPCAoYmwgPj4+IDApID8gMSA6IDApKTtcblx0ICAgICAgICAgICAgSDJsID0gSDIubG93ICA9IChIMmwgKyBjbCk7XG5cdCAgICAgICAgICAgIEgyLmhpZ2ggPSAoSDJoICsgY2ggKyAoKEgybCA+Pj4gMCkgPCAoY2wgPj4+IDApID8gMSA6IDApKTtcblx0ICAgICAgICAgICAgSDNsID0gSDMubG93ICA9IChIM2wgKyBkbCk7XG5cdCAgICAgICAgICAgIEgzLmhpZ2ggPSAoSDNoICsgZGggKyAoKEgzbCA+Pj4gMCkgPCAoZGwgPj4+IDApID8gMSA6IDApKTtcblx0ICAgICAgICAgICAgSDRsID0gSDQubG93ICA9IChINGwgKyBlbCk7XG5cdCAgICAgICAgICAgIEg0LmhpZ2ggPSAoSDRoICsgZWggKyAoKEg0bCA+Pj4gMCkgPCAoZWwgPj4+IDApID8gMSA6IDApKTtcblx0ICAgICAgICAgICAgSDVsID0gSDUubG93ICA9IChINWwgKyBmbCk7XG5cdCAgICAgICAgICAgIEg1LmhpZ2ggPSAoSDVoICsgZmggKyAoKEg1bCA+Pj4gMCkgPCAoZmwgPj4+IDApID8gMSA6IDApKTtcblx0ICAgICAgICAgICAgSDZsID0gSDYubG93ICA9IChINmwgKyBnbCk7XG5cdCAgICAgICAgICAgIEg2LmhpZ2ggPSAoSDZoICsgZ2ggKyAoKEg2bCA+Pj4gMCkgPCAoZ2wgPj4+IDApID8gMSA6IDApKTtcblx0ICAgICAgICAgICAgSDdsID0gSDcubG93ICA9IChIN2wgKyBobCk7XG5cdCAgICAgICAgICAgIEg3LmhpZ2ggPSAoSDdoICsgaGggKyAoKEg3bCA+Pj4gMCkgPCAoaGwgPj4+IDApID8gMSA6IDApKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvRmluYWxpemU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkYXRhID0gdGhpcy5fZGF0YTtcblx0ICAgICAgICAgICAgdmFyIGRhdGFXb3JkcyA9IGRhdGEud29yZHM7XG5cblx0ICAgICAgICAgICAgdmFyIG5CaXRzVG90YWwgPSB0aGlzLl9uRGF0YUJ5dGVzICogODtcblx0ICAgICAgICAgICAgdmFyIG5CaXRzTGVmdCA9IGRhdGEuc2lnQnl0ZXMgKiA4O1xuXG5cdCAgICAgICAgICAgIC8vIEFkZCBwYWRkaW5nXG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1tuQml0c0xlZnQgPj4+IDVdIHw9IDB4ODAgPDwgKDI0IC0gbkJpdHNMZWZ0ICUgMzIpO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKCgobkJpdHNMZWZ0ICsgMTI4KSA+Pj4gMTApIDw8IDUpICsgMzBdID0gTWF0aC5mbG9vcihuQml0c1RvdGFsIC8gMHgxMDAwMDAwMDApO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKCgobkJpdHNMZWZ0ICsgMTI4KSA+Pj4gMTApIDw8IDUpICsgMzFdID0gbkJpdHNUb3RhbDtcblx0ICAgICAgICAgICAgZGF0YS5zaWdCeXRlcyA9IGRhdGFXb3Jkcy5sZW5ndGggKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIEhhc2ggZmluYWwgYmxvY2tzXG5cdCAgICAgICAgICAgIHRoaXMuX3Byb2Nlc3MoKTtcblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0IGhhc2ggdG8gMzItYml0IHdvcmQgYXJyYXkgYmVmb3JlIHJldHVybmluZ1xuXHQgICAgICAgICAgICB2YXIgaGFzaCA9IHRoaXMuX2hhc2gudG9YMzIoKTtcblxuXHQgICAgICAgICAgICAvLyBSZXR1cm4gZmluYWwgY29tcHV0ZWQgaGFzaFxuXHQgICAgICAgICAgICByZXR1cm4gaGFzaDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgY2xvbmU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdmFyIGNsb25lID0gSGFzaGVyLmNsb25lLmNhbGwodGhpcyk7XG5cdCAgICAgICAgICAgIGNsb25lLl9oYXNoID0gdGhpcy5faGFzaC5jbG9uZSgpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBjbG9uZTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgYmxvY2tTaXplOiAxMDI0LzMyXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgaGFzaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlNIQTUxMignbWVzc2FnZScpO1xuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBNTEyKHdvcmRBcnJheSk7XG5cdCAgICAgKi9cblx0ICAgIEMuU0hBNTEyID0gSGFzaGVyLl9jcmVhdGVIZWxwZXIoU0hBNTEyKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgSE1BQydzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IGtleSBUaGUgc2VjcmV0IGtleS5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBITUFDLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaG1hYyA9IENyeXB0b0pTLkhtYWNTSEE1MTIobWVzc2FnZSwga2V5KTtcblx0ICAgICAqL1xuXHQgICAgQy5IbWFjU0hBNTEyID0gSGFzaGVyLl9jcmVhdGVIbWFjSGVscGVyKFNIQTUxMik7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuU0hBNTEyO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2VuYy1iYXNlNjRcIiksIHJlcXVpcmUoXCIuL21kNVwiKSwgcmVxdWlyZShcIi4vZXZwa2RmXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9lbmMtYmFzZTY0XCIsIFwiLi9tZDVcIiwgXCIuL2V2cGtkZlwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgQmxvY2tDaXBoZXIgPSBDX2xpYi5CbG9ja0NpcGhlcjtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cblx0ICAgIC8vIFBlcm11dGVkIENob2ljZSAxIGNvbnN0YW50c1xuXHQgICAgdmFyIFBDMSA9IFtcblx0ICAgICAgICA1NywgNDksIDQxLCAzMywgMjUsIDE3LCA5LCAgMSxcblx0ICAgICAgICA1OCwgNTAsIDQyLCAzNCwgMjYsIDE4LCAxMCwgMixcblx0ICAgICAgICA1OSwgNTEsIDQzLCAzNSwgMjcsIDE5LCAxMSwgMyxcblx0ICAgICAgICA2MCwgNTIsIDQ0LCAzNiwgNjMsIDU1LCA0NywgMzksXG5cdCAgICAgICAgMzEsIDIzLCAxNSwgNywgIDYyLCA1NCwgNDYsIDM4LFxuXHQgICAgICAgIDMwLCAyMiwgMTQsIDYsICA2MSwgNTMsIDQ1LCAzNyxcblx0ICAgICAgICAyOSwgMjEsIDEzLCA1LCAgMjgsIDIwLCAxMiwgNFxuXHQgICAgXTtcblxuXHQgICAgLy8gUGVybXV0ZWQgQ2hvaWNlIDIgY29uc3RhbnRzXG5cdCAgICB2YXIgUEMyID0gW1xuXHQgICAgICAgIDE0LCAxNywgMTEsIDI0LCAxLCAgNSxcblx0ICAgICAgICAzLCAgMjgsIDE1LCA2LCAgMjEsIDEwLFxuXHQgICAgICAgIDIzLCAxOSwgMTIsIDQsICAyNiwgOCxcblx0ICAgICAgICAxNiwgNywgIDI3LCAyMCwgMTMsIDIsXG5cdCAgICAgICAgNDEsIDUyLCAzMSwgMzcsIDQ3LCA1NSxcblx0ICAgICAgICAzMCwgNDAsIDUxLCA0NSwgMzMsIDQ4LFxuXHQgICAgICAgIDQ0LCA0OSwgMzksIDU2LCAzNCwgNTMsXG5cdCAgICAgICAgNDYsIDQyLCA1MCwgMzYsIDI5LCAzMlxuXHQgICAgXTtcblxuXHQgICAgLy8gQ3VtdWxhdGl2ZSBiaXQgc2hpZnQgY29uc3RhbnRzXG5cdCAgICB2YXIgQklUX1NISUZUUyA9IFsxLCAgMiwgIDQsICA2LCAgOCwgIDEwLCAxMiwgMTQsIDE1LCAxNywgMTksIDIxLCAyMywgMjUsIDI3LCAyOF07XG5cblx0ICAgIC8vIFNCT1hlcyBhbmQgcm91bmQgcGVybXV0YXRpb24gY29uc3RhbnRzXG5cdCAgICB2YXIgU0JPWF9QID0gW1xuXHQgICAgICAgIHtcblx0ICAgICAgICAgICAgMHgwOiAweDgwODIwMCxcblx0ICAgICAgICAgICAgMHgxMDAwMDAwMDogMHg4MDAwLFxuXHQgICAgICAgICAgICAweDIwMDAwMDAwOiAweDgwODAwMixcblx0ICAgICAgICAgICAgMHgzMDAwMDAwMDogMHgyLFxuXHQgICAgICAgICAgICAweDQwMDAwMDAwOiAweDIwMCxcblx0ICAgICAgICAgICAgMHg1MDAwMDAwMDogMHg4MDgyMDIsXG5cdCAgICAgICAgICAgIDB4NjAwMDAwMDA6IDB4ODAwMjAyLFxuXHQgICAgICAgICAgICAweDcwMDAwMDAwOiAweDgwMDAwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwMDogMHgyMDIsXG5cdCAgICAgICAgICAgIDB4OTAwMDAwMDA6IDB4ODAwMjAwLFxuXHQgICAgICAgICAgICAweGEwMDAwMDAwOiAweDgyMDAsXG5cdCAgICAgICAgICAgIDB4YjAwMDAwMDA6IDB4ODA4MDAwLFxuXHQgICAgICAgICAgICAweGMwMDAwMDAwOiAweDgwMDIsXG5cdCAgICAgICAgICAgIDB4ZDAwMDAwMDA6IDB4ODAwMDAyLFxuXHQgICAgICAgICAgICAweGUwMDAwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4ZjAwMDAwMDA6IDB4ODIwMixcblx0ICAgICAgICAgICAgMHg4MDAwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MTgwMDAwMDA6IDB4ODA4MjAyLFxuXHQgICAgICAgICAgICAweDI4MDAwMDAwOiAweDgyMDIsXG5cdCAgICAgICAgICAgIDB4MzgwMDAwMDA6IDB4ODAwMCxcblx0ICAgICAgICAgICAgMHg0ODAwMDAwMDogMHg4MDgyMDAsXG5cdCAgICAgICAgICAgIDB4NTgwMDAwMDA6IDB4MjAwLFxuXHQgICAgICAgICAgICAweDY4MDAwMDAwOiAweDgwODAwMixcblx0ICAgICAgICAgICAgMHg3ODAwMDAwMDogMHgyLFxuXHQgICAgICAgICAgICAweDg4MDAwMDAwOiAweDgwMDIwMCxcblx0ICAgICAgICAgICAgMHg5ODAwMDAwMDogMHg4MjAwLFxuXHQgICAgICAgICAgICAweGE4MDAwMDAwOiAweDgwODAwMCxcblx0ICAgICAgICAgICAgMHhiODAwMDAwMDogMHg4MDAyMDIsXG5cdCAgICAgICAgICAgIDB4YzgwMDAwMDA6IDB4ODAwMDAyLFxuXHQgICAgICAgICAgICAweGQ4MDAwMDAwOiAweDgwMDIsXG5cdCAgICAgICAgICAgIDB4ZTgwMDAwMDA6IDB4MjAyLFxuXHQgICAgICAgICAgICAweGY4MDAwMDAwOiAweDgwMDAwMCxcblx0ICAgICAgICAgICAgMHgxOiAweDgwMDAsXG5cdCAgICAgICAgICAgIDB4MTAwMDAwMDE6IDB4Mixcblx0ICAgICAgICAgICAgMHgyMDAwMDAwMTogMHg4MDgyMDAsXG5cdCAgICAgICAgICAgIDB4MzAwMDAwMDE6IDB4ODAwMDAwLFxuXHQgICAgICAgICAgICAweDQwMDAwMDAxOiAweDgwODAwMixcblx0ICAgICAgICAgICAgMHg1MDAwMDAwMTogMHg4MjAwLFxuXHQgICAgICAgICAgICAweDYwMDAwMDAxOiAweDIwMCxcblx0ICAgICAgICAgICAgMHg3MDAwMDAwMTogMHg4MDAyMDIsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMDE6IDB4ODA4MjAyLFxuXHQgICAgICAgICAgICAweDkwMDAwMDAxOiAweDgwODAwMCxcblx0ICAgICAgICAgICAgMHhhMDAwMDAwMTogMHg4MDAwMDIsXG5cdCAgICAgICAgICAgIDB4YjAwMDAwMDE6IDB4ODIwMixcblx0ICAgICAgICAgICAgMHhjMDAwMDAwMTogMHgyMDIsXG5cdCAgICAgICAgICAgIDB4ZDAwMDAwMDE6IDB4ODAwMjAwLFxuXHQgICAgICAgICAgICAweGUwMDAwMDAxOiAweDgwMDIsXG5cdCAgICAgICAgICAgIDB4ZjAwMDAwMDE6IDB4MCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxOiAweDgwODIwMixcblx0ICAgICAgICAgICAgMHgxODAwMDAwMTogMHg4MDgwMDAsXG5cdCAgICAgICAgICAgIDB4MjgwMDAwMDE6IDB4ODAwMDAwLFxuXHQgICAgICAgICAgICAweDM4MDAwMDAxOiAweDIwMCxcblx0ICAgICAgICAgICAgMHg0ODAwMDAwMTogMHg4MDAwLFxuXHQgICAgICAgICAgICAweDU4MDAwMDAxOiAweDgwMDAwMixcblx0ICAgICAgICAgICAgMHg2ODAwMDAwMTogMHgyLFxuXHQgICAgICAgICAgICAweDc4MDAwMDAxOiAweDgyMDIsXG5cdCAgICAgICAgICAgIDB4ODgwMDAwMDE6IDB4ODAwMixcblx0ICAgICAgICAgICAgMHg5ODAwMDAwMTogMHg4MDAyMDIsXG5cdCAgICAgICAgICAgIDB4YTgwMDAwMDE6IDB4MjAyLFxuXHQgICAgICAgICAgICAweGI4MDAwMDAxOiAweDgwODIwMCxcblx0ICAgICAgICAgICAgMHhjODAwMDAwMTogMHg4MDAyMDAsXG5cdCAgICAgICAgICAgIDB4ZDgwMDAwMDE6IDB4MCxcblx0ICAgICAgICAgICAgMHhlODAwMDAwMTogMHg4MjAwLFxuXHQgICAgICAgICAgICAweGY4MDAwMDAxOiAweDgwODAwMlxuXHQgICAgICAgIH0sXG5cdCAgICAgICAge1xuXHQgICAgICAgICAgICAweDA6IDB4NDAwODQwMTAsXG5cdCAgICAgICAgICAgIDB4MTAwMDAwMDogMHg0MDAwLFxuXHQgICAgICAgICAgICAweDIwMDAwMDA6IDB4ODAwMDAsXG5cdCAgICAgICAgICAgIDB4MzAwMDAwMDogMHg0MDA4MDAxMCxcblx0ICAgICAgICAgICAgMHg0MDAwMDAwOiAweDQwMDAwMDEwLFxuXHQgICAgICAgICAgICAweDUwMDAwMDA6IDB4NDAwODQwMDAsXG5cdCAgICAgICAgICAgIDB4NjAwMDAwMDogMHg0MDAwNDAwMCxcblx0ICAgICAgICAgICAgMHg3MDAwMDAwOiAweDEwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDA6IDB4ODQwMDAsXG5cdCAgICAgICAgICAgIDB4OTAwMDAwMDogMHg0MDAwNDAxMCxcblx0ICAgICAgICAgICAgMHhhMDAwMDAwOiAweDQwMDAwMDAwLFxuXHQgICAgICAgICAgICAweGIwMDAwMDA6IDB4ODQwMTAsXG5cdCAgICAgICAgICAgIDB4YzAwMDAwMDogMHg4MDAxMCxcblx0ICAgICAgICAgICAgMHhkMDAwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4ZTAwMDAwMDogMHg0MDEwLFxuXHQgICAgICAgICAgICAweGYwMDAwMDA6IDB4NDAwODAwMDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwOiAweDQwMDA0MDAwLFxuXHQgICAgICAgICAgICAweDE4MDAwMDA6IDB4ODQwMTAsXG5cdCAgICAgICAgICAgIDB4MjgwMDAwMDogMHgxMCxcblx0ICAgICAgICAgICAgMHgzODAwMDAwOiAweDQwMDA0MDEwLFxuXHQgICAgICAgICAgICAweDQ4MDAwMDA6IDB4NDAwODQwMTAsXG5cdCAgICAgICAgICAgIDB4NTgwMDAwMDogMHg0MDAwMDAwMCxcblx0ICAgICAgICAgICAgMHg2ODAwMDAwOiAweDgwMDAwLFxuXHQgICAgICAgICAgICAweDc4MDAwMDA6IDB4NDAwODAwMTAsXG5cdCAgICAgICAgICAgIDB4ODgwMDAwMDogMHg4MDAxMCxcblx0ICAgICAgICAgICAgMHg5ODAwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4YTgwMDAwMDogMHg0MDAwLFxuXHQgICAgICAgICAgICAweGI4MDAwMDA6IDB4NDAwODAwMDAsXG5cdCAgICAgICAgICAgIDB4YzgwMDAwMDogMHg0MDAwMDAxMCxcblx0ICAgICAgICAgICAgMHhkODAwMDAwOiAweDg0MDAwLFxuXHQgICAgICAgICAgICAweGU4MDAwMDA6IDB4NDAwODQwMDAsXG5cdCAgICAgICAgICAgIDB4ZjgwMDAwMDogMHg0MDEwLFxuXHQgICAgICAgICAgICAweDEwMDAwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MTEwMDAwMDA6IDB4NDAwODAwMTAsXG5cdCAgICAgICAgICAgIDB4MTIwMDAwMDA6IDB4NDAwMDQwMTAsXG5cdCAgICAgICAgICAgIDB4MTMwMDAwMDA6IDB4NDAwODQwMDAsXG5cdCAgICAgICAgICAgIDB4MTQwMDAwMDA6IDB4NDAwODAwMDAsXG5cdCAgICAgICAgICAgIDB4MTUwMDAwMDA6IDB4MTAsXG5cdCAgICAgICAgICAgIDB4MTYwMDAwMDA6IDB4ODQwMTAsXG5cdCAgICAgICAgICAgIDB4MTcwMDAwMDA6IDB4NDAwMCxcblx0ICAgICAgICAgICAgMHgxODAwMDAwMDogMHg0MDEwLFxuXHQgICAgICAgICAgICAweDE5MDAwMDAwOiAweDgwMDAwLFxuXHQgICAgICAgICAgICAweDFhMDAwMDAwOiAweDgwMDEwLFxuXHQgICAgICAgICAgICAweDFiMDAwMDAwOiAweDQwMDAwMDEwLFxuXHQgICAgICAgICAgICAweDFjMDAwMDAwOiAweDg0MDAwLFxuXHQgICAgICAgICAgICAweDFkMDAwMDAwOiAweDQwMDA0MDAwLFxuXHQgICAgICAgICAgICAweDFlMDAwMDAwOiAweDQwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDFmMDAwMDAwOiAweDQwMDg0MDEwLFxuXHQgICAgICAgICAgICAweDEwODAwMDAwOiAweDg0MDEwLFxuXHQgICAgICAgICAgICAweDExODAwMDAwOiAweDgwMDAwLFxuXHQgICAgICAgICAgICAweDEyODAwMDAwOiAweDQwMDgwMDAwLFxuXHQgICAgICAgICAgICAweDEzODAwMDAwOiAweDQwMDAsXG5cdCAgICAgICAgICAgIDB4MTQ4MDAwMDA6IDB4NDAwMDQwMDAsXG5cdCAgICAgICAgICAgIDB4MTU4MDAwMDA6IDB4NDAwODQwMTAsXG5cdCAgICAgICAgICAgIDB4MTY4MDAwMDA6IDB4MTAsXG5cdCAgICAgICAgICAgIDB4MTc4MDAwMDA6IDB4NDAwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTg4MDAwMDA6IDB4NDAwODQwMDAsXG5cdCAgICAgICAgICAgIDB4MTk4MDAwMDA6IDB4NDAwMDAwMTAsXG5cdCAgICAgICAgICAgIDB4MWE4MDAwMDA6IDB4NDAwMDQwMTAsXG5cdCAgICAgICAgICAgIDB4MWI4MDAwMDA6IDB4ODAwMTAsXG5cdCAgICAgICAgICAgIDB4MWM4MDAwMDA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxZDgwMDAwMDogMHg0MDEwLFxuXHQgICAgICAgICAgICAweDFlODAwMDAwOiAweDQwMDgwMDEwLFxuXHQgICAgICAgICAgICAweDFmODAwMDAwOiAweDg0MDAwXG5cdCAgICAgICAgfSxcblx0ICAgICAgICB7XG5cdCAgICAgICAgICAgIDB4MDogMHgxMDQsXG5cdCAgICAgICAgICAgIDB4MTAwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MjAwMDAwOiAweDQwMDAxMDAsXG5cdCAgICAgICAgICAgIDB4MzAwMDAwOiAweDEwMTA0LFxuXHQgICAgICAgICAgICAweDQwMDAwMDogMHgxMDAwNCxcblx0ICAgICAgICAgICAgMHg1MDAwMDA6IDB4NDAwMDAwNCxcblx0ICAgICAgICAgICAgMHg2MDAwMDA6IDB4NDAxMDEwNCxcblx0ICAgICAgICAgICAgMHg3MDAwMDA6IDB4NDAxMDAwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDA6IDB4NDAwMDAwMCxcblx0ICAgICAgICAgICAgMHg5MDAwMDA6IDB4NDAxMDEwMCxcblx0ICAgICAgICAgICAgMHhhMDAwMDA6IDB4MTAxMDAsXG5cdCAgICAgICAgICAgIDB4YjAwMDAwOiAweDQwMTAwMDQsXG5cdCAgICAgICAgICAgIDB4YzAwMDAwOiAweDQwMDAxMDQsXG5cdCAgICAgICAgICAgIDB4ZDAwMDAwOiAweDEwMDAwLFxuXHQgICAgICAgICAgICAweGUwMDAwMDogMHg0LFxuXHQgICAgICAgICAgICAweGYwMDAwMDogMHgxMDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDA6IDB4NDAxMDEwMCxcblx0ICAgICAgICAgICAgMHgxODAwMDA6IDB4NDAxMDAwNCxcblx0ICAgICAgICAgICAgMHgyODAwMDA6IDB4MCxcblx0ICAgICAgICAgICAgMHgzODAwMDA6IDB4NDAwMDEwMCxcblx0ICAgICAgICAgICAgMHg0ODAwMDA6IDB4NDAwMDAwNCxcblx0ICAgICAgICAgICAgMHg1ODAwMDA6IDB4MTAwMDAsXG5cdCAgICAgICAgICAgIDB4NjgwMDAwOiAweDEwMDA0LFxuXHQgICAgICAgICAgICAweDc4MDAwMDogMHgxMDQsXG5cdCAgICAgICAgICAgIDB4ODgwMDAwOiAweDQsXG5cdCAgICAgICAgICAgIDB4OTgwMDAwOiAweDEwMCxcblx0ICAgICAgICAgICAgMHhhODAwMDA6IDB4NDAxMDAwMCxcblx0ICAgICAgICAgICAgMHhiODAwMDA6IDB4MTAxMDQsXG5cdCAgICAgICAgICAgIDB4YzgwMDAwOiAweDEwMTAwLFxuXHQgICAgICAgICAgICAweGQ4MDAwMDogMHg0MDAwMTA0LFxuXHQgICAgICAgICAgICAweGU4MDAwMDogMHg0MDEwMTA0LFxuXHQgICAgICAgICAgICAweGY4MDAwMDogMHg0MDAwMDAwLFxuXHQgICAgICAgICAgICAweDEwMDAwMDA6IDB4NDAxMDEwMCxcblx0ICAgICAgICAgICAgMHgxMTAwMDAwOiAweDEwMDA0LFxuXHQgICAgICAgICAgICAweDEyMDAwMDA6IDB4MTAwMDAsXG5cdCAgICAgICAgICAgIDB4MTMwMDAwMDogMHg0MDAwMTAwLFxuXHQgICAgICAgICAgICAweDE0MDAwMDA6IDB4MTAwLFxuXHQgICAgICAgICAgICAweDE1MDAwMDA6IDB4NDAxMDEwNCxcblx0ICAgICAgICAgICAgMHgxNjAwMDAwOiAweDQwMDAwMDQsXG5cdCAgICAgICAgICAgIDB4MTcwMDAwMDogMHgwLFxuXHQgICAgICAgICAgICAweDE4MDAwMDA6IDB4NDAwMDEwNCxcblx0ICAgICAgICAgICAgMHgxOTAwMDAwOiAweDQwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MWEwMDAwMDogMHg0LFxuXHQgICAgICAgICAgICAweDFiMDAwMDA6IDB4MTAxMDAsXG5cdCAgICAgICAgICAgIDB4MWMwMDAwMDogMHg0MDEwMDAwLFxuXHQgICAgICAgICAgICAweDFkMDAwMDA6IDB4MTA0LFxuXHQgICAgICAgICAgICAweDFlMDAwMDA6IDB4MTAxMDQsXG5cdCAgICAgICAgICAgIDB4MWYwMDAwMDogMHg0MDEwMDA0LFxuXHQgICAgICAgICAgICAweDEwODAwMDA6IDB4NDAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxMTgwMDAwOiAweDEwNCxcblx0ICAgICAgICAgICAgMHgxMjgwMDAwOiAweDQwMTAxMDAsXG5cdCAgICAgICAgICAgIDB4MTM4MDAwMDogMHgwLFxuXHQgICAgICAgICAgICAweDE0ODAwMDA6IDB4MTAwMDQsXG5cdCAgICAgICAgICAgIDB4MTU4MDAwMDogMHg0MDAwMTAwLFxuXHQgICAgICAgICAgICAweDE2ODAwMDA6IDB4MTAwLFxuXHQgICAgICAgICAgICAweDE3ODAwMDA6IDB4NDAxMDAwNCxcblx0ICAgICAgICAgICAgMHgxODgwMDAwOiAweDEwMDAwLFxuXHQgICAgICAgICAgICAweDE5ODAwMDA6IDB4NDAxMDEwNCxcblx0ICAgICAgICAgICAgMHgxYTgwMDAwOiAweDEwMTA0LFxuXHQgICAgICAgICAgICAweDFiODAwMDA6IDB4NDAwMDAwNCxcblx0ICAgICAgICAgICAgMHgxYzgwMDAwOiAweDQwMDAxMDQsXG5cdCAgICAgICAgICAgIDB4MWQ4MDAwMDogMHg0MDEwMDAwLFxuXHQgICAgICAgICAgICAweDFlODAwMDA6IDB4NCxcblx0ICAgICAgICAgICAgMHgxZjgwMDAwOiAweDEwMTAwXG5cdCAgICAgICAgfSxcblx0ICAgICAgICB7XG5cdCAgICAgICAgICAgIDB4MDogMHg4MDQwMTAwMCxcblx0ICAgICAgICAgICAgMHgxMDAwMDogMHg4MDAwMTA0MCxcblx0ICAgICAgICAgICAgMHgyMDAwMDogMHg0MDEwNDAsXG5cdCAgICAgICAgICAgIDB4MzAwMDA6IDB4ODA0MDAwMDAsXG5cdCAgICAgICAgICAgIDB4NDAwMDA6IDB4MCxcblx0ICAgICAgICAgICAgMHg1MDAwMDogMHg0MDEwMDAsXG5cdCAgICAgICAgICAgIDB4NjAwMDA6IDB4ODAwMDAwNDAsXG5cdCAgICAgICAgICAgIDB4NzAwMDA6IDB4NDAwMDQwLFxuXHQgICAgICAgICAgICAweDgwMDAwOiAweDgwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDkwMDAwOiAweDQwMDAwMCxcblx0ICAgICAgICAgICAgMHhhMDAwMDogMHg0MCxcblx0ICAgICAgICAgICAgMHhiMDAwMDogMHg4MDAwMTAwMCxcblx0ICAgICAgICAgICAgMHhjMDAwMDogMHg4MDQwMDA0MCxcblx0ICAgICAgICAgICAgMHhkMDAwMDogMHgxMDQwLFxuXHQgICAgICAgICAgICAweGUwMDAwOiAweDEwMDAsXG5cdCAgICAgICAgICAgIDB4ZjAwMDA6IDB4ODA0MDEwNDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDogMHg4MDAwMTA0MCxcblx0ICAgICAgICAgICAgMHgxODAwMDogMHg0MCxcblx0ICAgICAgICAgICAgMHgyODAwMDogMHg4MDQwMDA0MCxcblx0ICAgICAgICAgICAgMHgzODAwMDogMHg4MDAwMTAwMCxcblx0ICAgICAgICAgICAgMHg0ODAwMDogMHg0MDEwMDAsXG5cdCAgICAgICAgICAgIDB4NTgwMDA6IDB4ODA0MDEwNDAsXG5cdCAgICAgICAgICAgIDB4NjgwMDA6IDB4MCxcblx0ICAgICAgICAgICAgMHg3ODAwMDogMHg4MDQwMDAwMCxcblx0ICAgICAgICAgICAgMHg4ODAwMDogMHgxMDAwLFxuXHQgICAgICAgICAgICAweDk4MDAwOiAweDgwNDAxMDAwLFxuXHQgICAgICAgICAgICAweGE4MDAwOiAweDQwMDAwMCxcblx0ICAgICAgICAgICAgMHhiODAwMDogMHgxMDQwLFxuXHQgICAgICAgICAgICAweGM4MDAwOiAweDgwMDAwMDAwLFxuXHQgICAgICAgICAgICAweGQ4MDAwOiAweDQwMDA0MCxcblx0ICAgICAgICAgICAgMHhlODAwMDogMHg0MDEwNDAsXG5cdCAgICAgICAgICAgIDB4ZjgwMDA6IDB4ODAwMDAwNDAsXG5cdCAgICAgICAgICAgIDB4MTAwMDAwOiAweDQwMDA0MCxcblx0ICAgICAgICAgICAgMHgxMTAwMDA6IDB4NDAxMDAwLFxuXHQgICAgICAgICAgICAweDEyMDAwMDogMHg4MDAwMDA0MCxcblx0ICAgICAgICAgICAgMHgxMzAwMDA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxNDAwMDA6IDB4MTA0MCxcblx0ICAgICAgICAgICAgMHgxNTAwMDA6IDB4ODA0MDAwNDAsXG5cdCAgICAgICAgICAgIDB4MTYwMDAwOiAweDgwNDAxMDAwLFxuXHQgICAgICAgICAgICAweDE3MDAwMDogMHg4MDAwMTA0MCxcblx0ICAgICAgICAgICAgMHgxODAwMDA6IDB4ODA0MDEwNDAsXG5cdCAgICAgICAgICAgIDB4MTkwMDAwOiAweDgwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDFhMDAwMDogMHg4MDQwMDAwMCxcblx0ICAgICAgICAgICAgMHgxYjAwMDA6IDB4NDAxMDQwLFxuXHQgICAgICAgICAgICAweDFjMDAwMDogMHg4MDAwMTAwMCxcblx0ICAgICAgICAgICAgMHgxZDAwMDA6IDB4NDAwMDAwLFxuXHQgICAgICAgICAgICAweDFlMDAwMDogMHg0MCxcblx0ICAgICAgICAgICAgMHgxZjAwMDA6IDB4MTAwMCxcblx0ICAgICAgICAgICAgMHgxMDgwMDA6IDB4ODA0MDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTE4MDAwOiAweDgwNDAxMDQwLFxuXHQgICAgICAgICAgICAweDEyODAwMDogMHgwLFxuXHQgICAgICAgICAgICAweDEzODAwMDogMHg0MDEwMDAsXG5cdCAgICAgICAgICAgIDB4MTQ4MDAwOiAweDQwMDA0MCxcblx0ICAgICAgICAgICAgMHgxNTgwMDA6IDB4ODAwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTY4MDAwOiAweDgwMDAxMDQwLFxuXHQgICAgICAgICAgICAweDE3ODAwMDogMHg0MCxcblx0ICAgICAgICAgICAgMHgxODgwMDA6IDB4ODAwMDAwNDAsXG5cdCAgICAgICAgICAgIDB4MTk4MDAwOiAweDEwMDAsXG5cdCAgICAgICAgICAgIDB4MWE4MDAwOiAweDgwMDAxMDAwLFxuXHQgICAgICAgICAgICAweDFiODAwMDogMHg4MDQwMDA0MCxcblx0ICAgICAgICAgICAgMHgxYzgwMDA6IDB4MTA0MCxcblx0ICAgICAgICAgICAgMHgxZDgwMDA6IDB4ODA0MDEwMDAsXG5cdCAgICAgICAgICAgIDB4MWU4MDAwOiAweDQwMDAwMCxcblx0ICAgICAgICAgICAgMHgxZjgwMDA6IDB4NDAxMDQwXG5cdCAgICAgICAgfSxcblx0ICAgICAgICB7XG5cdCAgICAgICAgICAgIDB4MDogMHg4MCxcblx0ICAgICAgICAgICAgMHgxMDAwOiAweDEwNDAwMDAsXG5cdCAgICAgICAgICAgIDB4MjAwMDogMHg0MDAwMCxcblx0ICAgICAgICAgICAgMHgzMDAwOiAweDIwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDQwMDA6IDB4MjAwNDAwODAsXG5cdCAgICAgICAgICAgIDB4NTAwMDogMHgxMDAwMDgwLFxuXHQgICAgICAgICAgICAweDYwMDA6IDB4MjEwMDAwODAsXG5cdCAgICAgICAgICAgIDB4NzAwMDogMHg0MDA4MCxcblx0ICAgICAgICAgICAgMHg4MDAwOiAweDEwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4OTAwMDogMHgyMDA0MDAwMCxcblx0ICAgICAgICAgICAgMHhhMDAwOiAweDIwMDAwMDgwLFxuXHQgICAgICAgICAgICAweGIwMDA6IDB4MjEwNDAwODAsXG5cdCAgICAgICAgICAgIDB4YzAwMDogMHgyMTA0MDAwMCxcblx0ICAgICAgICAgICAgMHhkMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4ZTAwMDogMHgxMDQwMDgwLFxuXHQgICAgICAgICAgICAweGYwMDA6IDB4MjEwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4ODAwOiAweDEwNDAwODAsXG5cdCAgICAgICAgICAgIDB4MTgwMDogMHgyMTAwMDA4MCxcblx0ICAgICAgICAgICAgMHgyODAwOiAweDgwLFxuXHQgICAgICAgICAgICAweDM4MDA6IDB4MTA0MDAwMCxcblx0ICAgICAgICAgICAgMHg0ODAwOiAweDQwMDAwLFxuXHQgICAgICAgICAgICAweDU4MDA6IDB4MjAwNDAwODAsXG5cdCAgICAgICAgICAgIDB4NjgwMDogMHgyMTA0MDAwMCxcblx0ICAgICAgICAgICAgMHg3ODAwOiAweDIwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDg4MDA6IDB4MjAwNDAwMDAsXG5cdCAgICAgICAgICAgIDB4OTgwMDogMHgwLFxuXHQgICAgICAgICAgICAweGE4MDA6IDB4MjEwNDAwODAsXG5cdCAgICAgICAgICAgIDB4YjgwMDogMHgxMDAwMDgwLFxuXHQgICAgICAgICAgICAweGM4MDA6IDB4MjAwMDAwODAsXG5cdCAgICAgICAgICAgIDB4ZDgwMDogMHgyMTAwMDAwMCxcblx0ICAgICAgICAgICAgMHhlODAwOiAweDEwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4ZjgwMDogMHg0MDA4MCxcblx0ICAgICAgICAgICAgMHgxMDAwMDogMHg0MDAwMCxcblx0ICAgICAgICAgICAgMHgxMTAwMDogMHg4MCxcblx0ICAgICAgICAgICAgMHgxMjAwMDogMHgyMDAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxMzAwMDogMHgyMTAwMDA4MCxcblx0ICAgICAgICAgICAgMHgxNDAwMDogMHgxMDAwMDgwLFxuXHQgICAgICAgICAgICAweDE1MDAwOiAweDIxMDQwMDAwLFxuXHQgICAgICAgICAgICAweDE2MDAwOiAweDIwMDQwMDgwLFxuXHQgICAgICAgICAgICAweDE3MDAwOiAweDEwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTgwMDA6IDB4MjEwNDAwODAsXG5cdCAgICAgICAgICAgIDB4MTkwMDA6IDB4MjEwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MWEwMDA6IDB4MTA0MDAwMCxcblx0ICAgICAgICAgICAgMHgxYjAwMDogMHgyMDA0MDAwMCxcblx0ICAgICAgICAgICAgMHgxYzAwMDogMHg0MDA4MCxcblx0ICAgICAgICAgICAgMHgxZDAwMDogMHgyMDAwMDA4MCxcblx0ICAgICAgICAgICAgMHgxZTAwMDogMHgwLFxuXHQgICAgICAgICAgICAweDFmMDAwOiAweDEwNDAwODAsXG5cdCAgICAgICAgICAgIDB4MTA4MDA6IDB4MjEwMDAwODAsXG5cdCAgICAgICAgICAgIDB4MTE4MDA6IDB4MTAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxMjgwMDogMHgxMDQwMDAwLFxuXHQgICAgICAgICAgICAweDEzODAwOiAweDIwMDQwMDgwLFxuXHQgICAgICAgICAgICAweDE0ODAwOiAweDIwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDE1ODAwOiAweDEwNDAwODAsXG5cdCAgICAgICAgICAgIDB4MTY4MDA6IDB4ODAsXG5cdCAgICAgICAgICAgIDB4MTc4MDA6IDB4MjEwNDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTg4MDA6IDB4NDAwODAsXG5cdCAgICAgICAgICAgIDB4MTk4MDA6IDB4MjEwNDAwODAsXG5cdCAgICAgICAgICAgIDB4MWE4MDA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxYjgwMDogMHgyMTAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxYzgwMDogMHgxMDAwMDgwLFxuXHQgICAgICAgICAgICAweDFkODAwOiAweDQwMDAwLFxuXHQgICAgICAgICAgICAweDFlODAwOiAweDIwMDQwMDAwLFxuXHQgICAgICAgICAgICAweDFmODAwOiAweDIwMDAwMDgwXG5cdCAgICAgICAgfSxcblx0ICAgICAgICB7XG5cdCAgICAgICAgICAgIDB4MDogMHgxMDAwMDAwOCxcblx0ICAgICAgICAgICAgMHgxMDA6IDB4MjAwMCxcblx0ICAgICAgICAgICAgMHgyMDA6IDB4MTAyMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MzAwOiAweDEwMjAyMDA4LFxuXHQgICAgICAgICAgICAweDQwMDogMHgxMDAwMjAwMCxcblx0ICAgICAgICAgICAgMHg1MDA6IDB4MjAwMDAwLFxuXHQgICAgICAgICAgICAweDYwMDogMHgyMDAwMDgsXG5cdCAgICAgICAgICAgIDB4NzAwOiAweDEwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDgwMDogMHgwLFxuXHQgICAgICAgICAgICAweDkwMDogMHgxMDAwMjAwOCxcblx0ICAgICAgICAgICAgMHhhMDA6IDB4MjAyMDAwLFxuXHQgICAgICAgICAgICAweGIwMDogMHg4LFxuXHQgICAgICAgICAgICAweGMwMDogMHgxMDIwMDAwOCxcblx0ICAgICAgICAgICAgMHhkMDA6IDB4MjAyMDA4LFxuXHQgICAgICAgICAgICAweGUwMDogMHgyMDA4LFxuXHQgICAgICAgICAgICAweGYwMDogMHgxMDIwMjAwMCxcblx0ICAgICAgICAgICAgMHg4MDogMHgxMDIwMDAwMCxcblx0ICAgICAgICAgICAgMHgxODA6IDB4MTAyMDIwMDgsXG5cdCAgICAgICAgICAgIDB4MjgwOiAweDgsXG5cdCAgICAgICAgICAgIDB4MzgwOiAweDIwMDAwMCxcblx0ICAgICAgICAgICAgMHg0ODA6IDB4MjAyMDA4LFxuXHQgICAgICAgICAgICAweDU4MDogMHgxMDAwMDAwOCxcblx0ICAgICAgICAgICAgMHg2ODA6IDB4MTAwMDIwMDAsXG5cdCAgICAgICAgICAgIDB4NzgwOiAweDIwMDgsXG5cdCAgICAgICAgICAgIDB4ODgwOiAweDIwMDAwOCxcblx0ICAgICAgICAgICAgMHg5ODA6IDB4MjAwMCxcblx0ICAgICAgICAgICAgMHhhODA6IDB4MTAwMDIwMDgsXG5cdCAgICAgICAgICAgIDB4YjgwOiAweDEwMjAwMDA4LFxuXHQgICAgICAgICAgICAweGM4MDogMHgwLFxuXHQgICAgICAgICAgICAweGQ4MDogMHgxMDIwMjAwMCxcblx0ICAgICAgICAgICAgMHhlODA6IDB4MjAyMDAwLFxuXHQgICAgICAgICAgICAweGY4MDogMHgxMDAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxMDAwOiAweDEwMDAyMDAwLFxuXHQgICAgICAgICAgICAweDExMDA6IDB4MTAyMDAwMDgsXG5cdCAgICAgICAgICAgIDB4MTIwMDogMHgxMDIwMjAwOCxcblx0ICAgICAgICAgICAgMHgxMzAwOiAweDIwMDgsXG5cdCAgICAgICAgICAgIDB4MTQwMDogMHgyMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTUwMDogMHgxMDAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxNjAwOiAweDEwMDAwMDA4LFxuXHQgICAgICAgICAgICAweDE3MDA6IDB4MjAyMDAwLFxuXHQgICAgICAgICAgICAweDE4MDA6IDB4MjAyMDA4LFxuXHQgICAgICAgICAgICAweDE5MDA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxYTAwOiAweDgsXG5cdCAgICAgICAgICAgIDB4MWIwMDogMHgxMDIwMDAwMCxcblx0ICAgICAgICAgICAgMHgxYzAwOiAweDIwMDAsXG5cdCAgICAgICAgICAgIDB4MWQwMDogMHgxMDAwMjAwOCxcblx0ICAgICAgICAgICAgMHgxZTAwOiAweDEwMjAyMDAwLFxuXHQgICAgICAgICAgICAweDFmMDA6IDB4MjAwMDA4LFxuXHQgICAgICAgICAgICAweDEwODA6IDB4OCxcblx0ICAgICAgICAgICAgMHgxMTgwOiAweDIwMjAwMCxcblx0ICAgICAgICAgICAgMHgxMjgwOiAweDIwMDAwMCxcblx0ICAgICAgICAgICAgMHgxMzgwOiAweDEwMDAwMDA4LFxuXHQgICAgICAgICAgICAweDE0ODA6IDB4MTAwMDIwMDAsXG5cdCAgICAgICAgICAgIDB4MTU4MDogMHgyMDA4LFxuXHQgICAgICAgICAgICAweDE2ODA6IDB4MTAyMDIwMDgsXG5cdCAgICAgICAgICAgIDB4MTc4MDogMHgxMDIwMDAwMCxcblx0ICAgICAgICAgICAgMHgxODgwOiAweDEwMjAyMDAwLFxuXHQgICAgICAgICAgICAweDE5ODA6IDB4MTAyMDAwMDgsXG5cdCAgICAgICAgICAgIDB4MWE4MDogMHgyMDAwLFxuXHQgICAgICAgICAgICAweDFiODA6IDB4MjAyMDA4LFxuXHQgICAgICAgICAgICAweDFjODA6IDB4MjAwMDA4LFxuXHQgICAgICAgICAgICAweDFkODA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxZTgwOiAweDEwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDFmODA6IDB4MTAwMDIwMDhcblx0ICAgICAgICB9LFxuXHQgICAgICAgIHtcblx0ICAgICAgICAgICAgMHgwOiAweDEwMDAwMCxcblx0ICAgICAgICAgICAgMHgxMDogMHgyMDAwNDAxLFxuXHQgICAgICAgICAgICAweDIwOiAweDQwMCxcblx0ICAgICAgICAgICAgMHgzMDogMHgxMDA0MDEsXG5cdCAgICAgICAgICAgIDB4NDA6IDB4MjEwMDQwMSxcblx0ICAgICAgICAgICAgMHg1MDogMHgwLFxuXHQgICAgICAgICAgICAweDYwOiAweDEsXG5cdCAgICAgICAgICAgIDB4NzA6IDB4MjEwMDAwMSxcblx0ICAgICAgICAgICAgMHg4MDogMHgyMDAwNDAwLFxuXHQgICAgICAgICAgICAweDkwOiAweDEwMDAwMSxcblx0ICAgICAgICAgICAgMHhhMDogMHgyMDAwMDAxLFxuXHQgICAgICAgICAgICAweGIwOiAweDIxMDA0MDAsXG5cdCAgICAgICAgICAgIDB4YzA6IDB4MjEwMDAwMCxcblx0ICAgICAgICAgICAgMHhkMDogMHg0MDEsXG5cdCAgICAgICAgICAgIDB4ZTA6IDB4MTAwNDAwLFxuXHQgICAgICAgICAgICAweGYwOiAweDIwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4ODogMHgyMTAwMDAxLFxuXHQgICAgICAgICAgICAweDE4OiAweDAsXG5cdCAgICAgICAgICAgIDB4Mjg6IDB4MjAwMDQwMSxcblx0ICAgICAgICAgICAgMHgzODogMHgyMTAwNDAwLFxuXHQgICAgICAgICAgICAweDQ4OiAweDEwMDAwMCxcblx0ICAgICAgICAgICAgMHg1ODogMHgyMDAwMDAxLFxuXHQgICAgICAgICAgICAweDY4OiAweDIwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4Nzg6IDB4NDAxLFxuXHQgICAgICAgICAgICAweDg4OiAweDEwMDQwMSxcblx0ICAgICAgICAgICAgMHg5ODogMHgyMDAwNDAwLFxuXHQgICAgICAgICAgICAweGE4OiAweDIxMDAwMDAsXG5cdCAgICAgICAgICAgIDB4Yjg6IDB4MTAwMDAxLFxuXHQgICAgICAgICAgICAweGM4OiAweDQwMCxcblx0ICAgICAgICAgICAgMHhkODogMHgyMTAwNDAxLFxuXHQgICAgICAgICAgICAweGU4OiAweDEsXG5cdCAgICAgICAgICAgIDB4Zjg6IDB4MTAwNDAwLFxuXHQgICAgICAgICAgICAweDEwMDogMHgyMDAwMDAwLFxuXHQgICAgICAgICAgICAweDExMDogMHgxMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTIwOiAweDIwMDA0MDEsXG5cdCAgICAgICAgICAgIDB4MTMwOiAweDIxMDAwMDEsXG5cdCAgICAgICAgICAgIDB4MTQwOiAweDEwMDAwMSxcblx0ICAgICAgICAgICAgMHgxNTA6IDB4MjAwMDQwMCxcblx0ICAgICAgICAgICAgMHgxNjA6IDB4MjEwMDQwMCxcblx0ICAgICAgICAgICAgMHgxNzA6IDB4MTAwNDAxLFxuXHQgICAgICAgICAgICAweDE4MDogMHg0MDEsXG5cdCAgICAgICAgICAgIDB4MTkwOiAweDIxMDA0MDEsXG5cdCAgICAgICAgICAgIDB4MWEwOiAweDEwMDQwMCxcblx0ICAgICAgICAgICAgMHgxYjA6IDB4MSxcblx0ICAgICAgICAgICAgMHgxYzA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxZDA6IDB4MjEwMDAwMCxcblx0ICAgICAgICAgICAgMHgxZTA6IDB4MjAwMDAwMSxcblx0ICAgICAgICAgICAgMHgxZjA6IDB4NDAwLFxuXHQgICAgICAgICAgICAweDEwODogMHgxMDA0MDAsXG5cdCAgICAgICAgICAgIDB4MTE4OiAweDIwMDA0MDEsXG5cdCAgICAgICAgICAgIDB4MTI4OiAweDIxMDAwMDEsXG5cdCAgICAgICAgICAgIDB4MTM4OiAweDEsXG5cdCAgICAgICAgICAgIDB4MTQ4OiAweDIwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTU4OiAweDEwMDAwMCxcblx0ICAgICAgICAgICAgMHgxNjg6IDB4NDAxLFxuXHQgICAgICAgICAgICAweDE3ODogMHgyMTAwNDAwLFxuXHQgICAgICAgICAgICAweDE4ODogMHgyMDAwMDAxLFxuXHQgICAgICAgICAgICAweDE5ODogMHgyMTAwMDAwLFxuXHQgICAgICAgICAgICAweDFhODogMHgwLFxuXHQgICAgICAgICAgICAweDFiODogMHgyMTAwNDAxLFxuXHQgICAgICAgICAgICAweDFjODogMHgxMDA0MDEsXG5cdCAgICAgICAgICAgIDB4MWQ4OiAweDQwMCxcblx0ICAgICAgICAgICAgMHgxZTg6IDB4MjAwMDQwMCxcblx0ICAgICAgICAgICAgMHgxZjg6IDB4MTAwMDAxXG5cdCAgICAgICAgfSxcblx0ICAgICAgICB7XG5cdCAgICAgICAgICAgIDB4MDogMHg4MDAwODIwLFxuXHQgICAgICAgICAgICAweDE6IDB4MjAwMDAsXG5cdCAgICAgICAgICAgIDB4MjogMHg4MDAwMDAwLFxuXHQgICAgICAgICAgICAweDM6IDB4MjAsXG5cdCAgICAgICAgICAgIDB4NDogMHgyMDAyMCxcblx0ICAgICAgICAgICAgMHg1OiAweDgwMjA4MjAsXG5cdCAgICAgICAgICAgIDB4NjogMHg4MDIwODAwLFxuXHQgICAgICAgICAgICAweDc6IDB4ODAwLFxuXHQgICAgICAgICAgICAweDg6IDB4ODAyMDAwMCxcblx0ICAgICAgICAgICAgMHg5OiAweDgwMDA4MDAsXG5cdCAgICAgICAgICAgIDB4YTogMHgyMDgwMCxcblx0ICAgICAgICAgICAgMHhiOiAweDgwMjAwMjAsXG5cdCAgICAgICAgICAgIDB4YzogMHg4MjAsXG5cdCAgICAgICAgICAgIDB4ZDogMHgwLFxuXHQgICAgICAgICAgICAweGU6IDB4ODAwMDAyMCxcblx0ICAgICAgICAgICAgMHhmOiAweDIwODIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDAwOiAweDgwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwMTogMHg4MDIwODIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDAyOiAweDgwMDA4MjAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMDM6IDB4ODAwMDAwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwNDogMHg4MDIwMDAwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDA1OiAweDIwODAwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDA2OiAweDIwODIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDA3OiAweDIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDA4OiAweDgwMDAwMjAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMDk6IDB4ODIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDBhOiAweDIwMDIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDBiOiAweDgwMjA4MDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMGM6IDB4MCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwZDogMHg4MDIwMDIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDBlOiAweDgwMDA4MDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMGY6IDB4MjAwMDAsXG5cdCAgICAgICAgICAgIDB4MTA6IDB4MjA4MjAsXG5cdCAgICAgICAgICAgIDB4MTE6IDB4ODAyMDgwMCxcblx0ICAgICAgICAgICAgMHgxMjogMHgyMCxcblx0ICAgICAgICAgICAgMHgxMzogMHg4MDAsXG5cdCAgICAgICAgICAgIDB4MTQ6IDB4ODAwMDgwMCxcblx0ICAgICAgICAgICAgMHgxNTogMHg4MDAwMDIwLFxuXHQgICAgICAgICAgICAweDE2OiAweDgwMjAwMjAsXG5cdCAgICAgICAgICAgIDB4MTc6IDB4MjAwMDAsXG5cdCAgICAgICAgICAgIDB4MTg6IDB4MCxcblx0ICAgICAgICAgICAgMHgxOTogMHgyMDAyMCxcblx0ICAgICAgICAgICAgMHgxYTogMHg4MDIwMDAwLFxuXHQgICAgICAgICAgICAweDFiOiAweDgwMDA4MjAsXG5cdCAgICAgICAgICAgIDB4MWM6IDB4ODAyMDgyMCxcblx0ICAgICAgICAgICAgMHgxZDogMHgyMDgwMCxcblx0ICAgICAgICAgICAgMHgxZTogMHg4MjAsXG5cdCAgICAgICAgICAgIDB4MWY6IDB4ODAwMDAwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxMDogMHgyMDAwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxMTogMHg4MDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMTI6IDB4ODAyMDAyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxMzogMHgyMDgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxNDogMHgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxNTogMHg4MDIwMDAwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDE2OiAweDgwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMTc6IDB4ODAwMDgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxODogMHg4MDIwODIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDE5OiAweDgwMDAwMjAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMWE6IDB4ODAwMDgwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxYjogMHgwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDFjOiAweDIwODAwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDFkOiAweDgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxZTogMHgyMDAyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxZjogMHg4MDIwODAwXG5cdCAgICAgICAgfVxuXHQgICAgXTtcblxuXHQgICAgLy8gTWFza3MgdGhhdCBzZWxlY3QgdGhlIFNCT1ggaW5wdXRcblx0ICAgIHZhciBTQk9YX01BU0sgPSBbXG5cdCAgICAgICAgMHhmODAwMDAwMSwgMHgxZjgwMDAwMCwgMHgwMWY4MDAwMCwgMHgwMDFmODAwMCxcblx0ICAgICAgICAweDAwMDFmODAwLCAweDAwMDAxZjgwLCAweDAwMDAwMWY4LCAweDgwMDAwMDFmXG5cdCAgICBdO1xuXG5cdCAgICAvKipcblx0ICAgICAqIERFUyBibG9jayBjaXBoZXIgYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgREVTID0gQ19hbGdvLkRFUyA9IEJsb2NrQ2lwaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgX2RvUmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBrZXkgPSB0aGlzLl9rZXk7XG5cdCAgICAgICAgICAgIHZhciBrZXlXb3JkcyA9IGtleS53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBTZWxlY3QgNTYgYml0cyBhY2NvcmRpbmcgdG8gUEMxXG5cdCAgICAgICAgICAgIHZhciBrZXlCaXRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgNTY7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgdmFyIGtleUJpdFBvcyA9IFBDMVtpXSAtIDE7XG5cdCAgICAgICAgICAgICAgICBrZXlCaXRzW2ldID0gKGtleVdvcmRzW2tleUJpdFBvcyA+Pj4gNV0gPj4+ICgzMSAtIGtleUJpdFBvcyAlIDMyKSkgJiAxO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gQXNzZW1ibGUgMTYgc3Via2V5c1xuXHQgICAgICAgICAgICB2YXIgc3ViS2V5cyA9IHRoaXMuX3N1YktleXMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgblN1YktleSA9IDA7IG5TdWJLZXkgPCAxNjsgblN1YktleSsrKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBDcmVhdGUgc3Via2V5XG5cdCAgICAgICAgICAgICAgICB2YXIgc3ViS2V5ID0gc3ViS2V5c1tuU3ViS2V5XSA9IFtdO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICAgICAgdmFyIGJpdFNoaWZ0ID0gQklUX1NISUZUU1tuU3ViS2V5XTtcblxuXHQgICAgICAgICAgICAgICAgLy8gU2VsZWN0IDQ4IGJpdHMgYWNjb3JkaW5nIHRvIFBDMlxuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgLy8gU2VsZWN0IGZyb20gdGhlIGxlZnQgMjgga2V5IGJpdHNcblx0ICAgICAgICAgICAgICAgICAgICBzdWJLZXlbKGkgLyA2KSB8IDBdIHw9IGtleUJpdHNbKChQQzJbaV0gLSAxKSArIGJpdFNoaWZ0KSAlIDI4XSA8PCAoMzEgLSBpICUgNik7XG5cblx0ICAgICAgICAgICAgICAgICAgICAvLyBTZWxlY3QgZnJvbSB0aGUgcmlnaHQgMjgga2V5IGJpdHNcblx0ICAgICAgICAgICAgICAgICAgICBzdWJLZXlbNCArICgoaSAvIDYpIHwgMCldIHw9IGtleUJpdHNbMjggKyAoKChQQzJbaSArIDI0XSAtIDEpICsgYml0U2hpZnQpICUgMjgpXSA8PCAoMzEgLSBpICUgNik7XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIC8vIFNpbmNlIGVhY2ggc3Via2V5IGlzIGFwcGxpZWQgdG8gYW4gZXhwYW5kZWQgMzItYml0IGlucHV0LFxuXHQgICAgICAgICAgICAgICAgLy8gdGhlIHN1YmtleSBjYW4gYmUgYnJva2VuIGludG8gOCB2YWx1ZXMgc2NhbGVkIHRvIDMyLWJpdHMsXG5cdCAgICAgICAgICAgICAgICAvLyB3aGljaCBhbGxvd3MgdGhlIGtleSB0byBiZSB1c2VkIHdpdGhvdXQgZXhwYW5zaW9uXG5cdCAgICAgICAgICAgICAgICBzdWJLZXlbMF0gPSAoc3ViS2V5WzBdIDw8IDEpIHwgKHN1YktleVswXSA+Pj4gMzEpO1xuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDE7IGkgPCA3OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgICAgICBzdWJLZXlbaV0gPSBzdWJLZXlbaV0gPj4+ICgoaSAtIDEpICogNCArIDMpO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgc3ViS2V5WzddID0gKHN1YktleVs3XSA8PCA1KSB8IChzdWJLZXlbN10gPj4+IDI3KTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgaW52ZXJzZSBzdWJrZXlzXG5cdCAgICAgICAgICAgIHZhciBpbnZTdWJLZXlzID0gdGhpcy5faW52U3ViS2V5cyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDE2OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIGludlN1YktleXNbaV0gPSBzdWJLZXlzWzE1IC0gaV07XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgZW5jcnlwdEJsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIHRoaXMuX2RvQ3J5cHRCbG9jayhNLCBvZmZzZXQsIHRoaXMuX3N1YktleXMpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBkZWNyeXB0QmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgdGhpcy5fZG9DcnlwdEJsb2NrKE0sIG9mZnNldCwgdGhpcy5faW52U3ViS2V5cyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0NyeXB0QmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQsIHN1YktleXMpIHtcblx0ICAgICAgICAgICAgLy8gR2V0IGlucHV0XG5cdCAgICAgICAgICAgIHRoaXMuX2xCbG9jayA9IE1bb2Zmc2V0XTtcblx0ICAgICAgICAgICAgdGhpcy5fckJsb2NrID0gTVtvZmZzZXQgKyAxXTtcblxuXHQgICAgICAgICAgICAvLyBJbml0aWFsIHBlcm11dGF0aW9uXG5cdCAgICAgICAgICAgIGV4Y2hhbmdlTFIuY2FsbCh0aGlzLCA0LCAgMHgwZjBmMGYwZik7XG5cdCAgICAgICAgICAgIGV4Y2hhbmdlTFIuY2FsbCh0aGlzLCAxNiwgMHgwMDAwZmZmZik7XG5cdCAgICAgICAgICAgIGV4Y2hhbmdlUkwuY2FsbCh0aGlzLCAyLCAgMHgzMzMzMzMzMyk7XG5cdCAgICAgICAgICAgIGV4Y2hhbmdlUkwuY2FsbCh0aGlzLCA4LCAgMHgwMGZmMDBmZik7XG5cdCAgICAgICAgICAgIGV4Y2hhbmdlTFIuY2FsbCh0aGlzLCAxLCAgMHg1NTU1NTU1NSk7XG5cblx0ICAgICAgICAgICAgLy8gUm91bmRzXG5cdCAgICAgICAgICAgIGZvciAodmFyIHJvdW5kID0gMDsgcm91bmQgPCAxNjsgcm91bmQrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgICAgICB2YXIgc3ViS2V5ID0gc3ViS2V5c1tyb3VuZF07XG5cdCAgICAgICAgICAgICAgICB2YXIgbEJsb2NrID0gdGhpcy5fbEJsb2NrO1xuXHQgICAgICAgICAgICAgICAgdmFyIHJCbG9jayA9IHRoaXMuX3JCbG9jaztcblxuXHQgICAgICAgICAgICAgICAgLy8gRmVpc3RlbCBmdW5jdGlvblxuXHQgICAgICAgICAgICAgICAgdmFyIGYgPSAwO1xuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgICAgICBmIHw9IFNCT1hfUFtpXVsoKHJCbG9jayBeIHN1YktleVtpXSkgJiBTQk9YX01BU0tbaV0pID4+PiAwXTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIHRoaXMuX2xCbG9jayA9IHJCbG9jaztcblx0ICAgICAgICAgICAgICAgIHRoaXMuX3JCbG9jayA9IGxCbG9jayBeIGY7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBVbmRvIHN3YXAgZnJvbSBsYXN0IHJvdW5kXG5cdCAgICAgICAgICAgIHZhciB0ID0gdGhpcy5fbEJsb2NrO1xuXHQgICAgICAgICAgICB0aGlzLl9sQmxvY2sgPSB0aGlzLl9yQmxvY2s7XG5cdCAgICAgICAgICAgIHRoaXMuX3JCbG9jayA9IHQ7XG5cblx0ICAgICAgICAgICAgLy8gRmluYWwgcGVybXV0YXRpb25cblx0ICAgICAgICAgICAgZXhjaGFuZ2VMUi5jYWxsKHRoaXMsIDEsICAweDU1NTU1NTU1KTtcblx0ICAgICAgICAgICAgZXhjaGFuZ2VSTC5jYWxsKHRoaXMsIDgsICAweDAwZmYwMGZmKTtcblx0ICAgICAgICAgICAgZXhjaGFuZ2VSTC5jYWxsKHRoaXMsIDIsICAweDMzMzMzMzMzKTtcblx0ICAgICAgICAgICAgZXhjaGFuZ2VMUi5jYWxsKHRoaXMsIDE2LCAweDAwMDBmZmZmKTtcblx0ICAgICAgICAgICAgZXhjaGFuZ2VMUi5jYWxsKHRoaXMsIDQsICAweDBmMGYwZjBmKTtcblxuXHQgICAgICAgICAgICAvLyBTZXQgb3V0cHV0XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0XSA9IHRoaXMuX2xCbG9jaztcblx0ICAgICAgICAgICAgTVtvZmZzZXQgKyAxXSA9IHRoaXMuX3JCbG9jaztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAga2V5U2l6ZTogNjQvMzIsXG5cblx0ICAgICAgICBpdlNpemU6IDY0LzMyLFxuXG5cdCAgICAgICAgYmxvY2tTaXplOiA2NC8zMlxuXHQgICAgfSk7XG5cblx0ICAgIC8vIFN3YXAgYml0cyBhY3Jvc3MgdGhlIGxlZnQgYW5kIHJpZ2h0IHdvcmRzXG5cdCAgICBmdW5jdGlvbiBleGNoYW5nZUxSKG9mZnNldCwgbWFzaykge1xuXHQgICAgICAgIHZhciB0ID0gKCh0aGlzLl9sQmxvY2sgPj4+IG9mZnNldCkgXiB0aGlzLl9yQmxvY2spICYgbWFzaztcblx0ICAgICAgICB0aGlzLl9yQmxvY2sgXj0gdDtcblx0ICAgICAgICB0aGlzLl9sQmxvY2sgXj0gdCA8PCBvZmZzZXQ7XG5cdCAgICB9XG5cblx0ICAgIGZ1bmN0aW9uIGV4Y2hhbmdlUkwob2Zmc2V0LCBtYXNrKSB7XG5cdCAgICAgICAgdmFyIHQgPSAoKHRoaXMuX3JCbG9jayA+Pj4gb2Zmc2V0KSBeIHRoaXMuX2xCbG9jaykgJiBtYXNrO1xuXHQgICAgICAgIHRoaXMuX2xCbG9jayBePSB0O1xuXHQgICAgICAgIHRoaXMuX3JCbG9jayBePSB0IDw8IG9mZnNldDtcblx0ICAgIH1cblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbnMgdG8gdGhlIGNpcGhlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGNpcGhlcnRleHQgPSBDcnlwdG9KUy5ERVMuZW5jcnlwdChtZXNzYWdlLCBrZXksIGNmZyk7XG5cdCAgICAgKiAgICAgdmFyIHBsYWludGV4dCAgPSBDcnlwdG9KUy5ERVMuZGVjcnlwdChjaXBoZXJ0ZXh0LCBrZXksIGNmZyk7XG5cdCAgICAgKi9cblx0ICAgIEMuREVTID0gQmxvY2tDaXBoZXIuX2NyZWF0ZUhlbHBlcihERVMpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFRyaXBsZS1ERVMgYmxvY2sgY2lwaGVyIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFRyaXBsZURFUyA9IENfYWxnby5UcmlwbGVERVMgPSBCbG9ja0NpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIga2V5ID0gdGhpcy5fa2V5O1xuXHQgICAgICAgICAgICB2YXIga2V5V29yZHMgPSBrZXkud29yZHM7XG5cblx0ICAgICAgICAgICAgLy8gQ3JlYXRlIERFUyBpbnN0YW5jZXNcblx0ICAgICAgICAgICAgdGhpcy5fZGVzMSA9IERFUy5jcmVhdGVFbmNyeXB0b3IoV29yZEFycmF5LmNyZWF0ZShrZXlXb3Jkcy5zbGljZSgwLCAyKSkpO1xuXHQgICAgICAgICAgICB0aGlzLl9kZXMyID0gREVTLmNyZWF0ZUVuY3J5cHRvcihXb3JkQXJyYXkuY3JlYXRlKGtleVdvcmRzLnNsaWNlKDIsIDQpKSk7XG5cdCAgICAgICAgICAgIHRoaXMuX2RlczMgPSBERVMuY3JlYXRlRW5jcnlwdG9yKFdvcmRBcnJheS5jcmVhdGUoa2V5V29yZHMuc2xpY2UoNCwgNikpKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgZW5jcnlwdEJsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIHRoaXMuX2RlczEuZW5jcnlwdEJsb2NrKE0sIG9mZnNldCk7XG5cdCAgICAgICAgICAgIHRoaXMuX2RlczIuZGVjcnlwdEJsb2NrKE0sIG9mZnNldCk7XG5cdCAgICAgICAgICAgIHRoaXMuX2RlczMuZW5jcnlwdEJsb2NrKE0sIG9mZnNldCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGRlY3J5cHRCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICB0aGlzLl9kZXMzLmRlY3J5cHRCbG9jayhNLCBvZmZzZXQpO1xuXHQgICAgICAgICAgICB0aGlzLl9kZXMyLmVuY3J5cHRCbG9jayhNLCBvZmZzZXQpO1xuXHQgICAgICAgICAgICB0aGlzLl9kZXMxLmRlY3J5cHRCbG9jayhNLCBvZmZzZXQpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBrZXlTaXplOiAxOTIvMzIsXG5cblx0ICAgICAgICBpdlNpemU6IDY0LzMyLFxuXG5cdCAgICAgICAgYmxvY2tTaXplOiA2NC8zMlxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb25zIHRvIHRoZSBjaXBoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0ID0gQ3J5cHRvSlMuVHJpcGxlREVTLmVuY3J5cHQobWVzc2FnZSwga2V5LCBjZmcpO1xuXHQgICAgICogICAgIHZhciBwbGFpbnRleHQgID0gQ3J5cHRvSlMuVHJpcGxlREVTLmRlY3J5cHQoY2lwaGVydGV4dCwga2V5LCBjZmcpO1xuXHQgICAgICovXG5cdCAgICBDLlRyaXBsZURFUyA9IEJsb2NrQ2lwaGVyLl9jcmVhdGVIZWxwZXIoVHJpcGxlREVTKTtcblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5UcmlwbGVERVM7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5KSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAodW5kZWZpbmVkKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBCYXNlID0gQ19saWIuQmFzZTtcblx0ICAgIHZhciBYMzJXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogeDY0IG5hbWVzcGFjZS5cblx0ICAgICAqL1xuXHQgICAgdmFyIENfeDY0ID0gQy54NjQgPSB7fTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBIDY0LWJpdCB3b3JkLlxuXHQgICAgICovXG5cdCAgICB2YXIgWDY0V29yZCA9IENfeDY0LldvcmQgPSBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogSW5pdGlhbGl6ZXMgYSBuZXdseSBjcmVhdGVkIDY0LWJpdCB3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IGhpZ2ggVGhlIGhpZ2ggMzIgYml0cy5cblx0ICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0gbG93IFRoZSBsb3cgMzIgYml0cy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHg2NFdvcmQgPSBDcnlwdG9KUy54NjQuV29yZC5jcmVhdGUoMHgwMDAxMDIwMywgMHgwNDA1MDYwNyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKGhpZ2gsIGxvdykge1xuXHQgICAgICAgICAgICB0aGlzLmhpZ2ggPSBoaWdoO1xuXHQgICAgICAgICAgICB0aGlzLmxvdyA9IGxvdztcblx0ICAgICAgICB9XG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBCaXR3aXNlIE5PVHMgdGhpcyB3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7WDY0V29yZH0gQSBuZXcgeDY0LVdvcmQgb2JqZWN0IGFmdGVyIG5lZ2F0aW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgbmVnYXRlZCA9IHg2NFdvcmQubm90KCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgLy8gbm90OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIHZhciBoaWdoID0gfnRoaXMuaGlnaDtcblx0ICAgICAgICAgICAgLy8gdmFyIGxvdyA9IH50aGlzLmxvdztcblxuXHQgICAgICAgICAgICAvLyByZXR1cm4gWDY0V29yZC5jcmVhdGUoaGlnaCwgbG93KTtcblx0ICAgICAgICAvLyB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQml0d2lzZSBBTkRzIHRoaXMgd29yZCB3aXRoIHRoZSBwYXNzZWQgd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7WDY0V29yZH0gd29yZCBUaGUgeDY0LVdvcmQgdG8gQU5EIHdpdGggdGhpcyB3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7WDY0V29yZH0gQSBuZXcgeDY0LVdvcmQgb2JqZWN0IGFmdGVyIEFORGluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGFuZGVkID0geDY0V29yZC5hbmQoYW5vdGhlclg2NFdvcmQpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIC8vIGFuZDogZnVuY3Rpb24gKHdvcmQpIHtcblx0ICAgICAgICAgICAgLy8gdmFyIGhpZ2ggPSB0aGlzLmhpZ2ggJiB3b3JkLmhpZ2g7XG5cdCAgICAgICAgICAgIC8vIHZhciBsb3cgPSB0aGlzLmxvdyAmIHdvcmQubG93O1xuXG5cdCAgICAgICAgICAgIC8vIHJldHVybiBYNjRXb3JkLmNyZWF0ZShoaWdoLCBsb3cpO1xuXHQgICAgICAgIC8vIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBCaXR3aXNlIE9ScyB0aGlzIHdvcmQgd2l0aCB0aGUgcGFzc2VkIHdvcmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1g2NFdvcmR9IHdvcmQgVGhlIHg2NC1Xb3JkIHRvIE9SIHdpdGggdGhpcyB3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7WDY0V29yZH0gQSBuZXcgeDY0LVdvcmQgb2JqZWN0IGFmdGVyIE9SaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgb3JlZCA9IHg2NFdvcmQub3IoYW5vdGhlclg2NFdvcmQpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIC8vIG9yOiBmdW5jdGlvbiAod29yZCkge1xuXHQgICAgICAgICAgICAvLyB2YXIgaGlnaCA9IHRoaXMuaGlnaCB8IHdvcmQuaGlnaDtcblx0ICAgICAgICAgICAgLy8gdmFyIGxvdyA9IHRoaXMubG93IHwgd29yZC5sb3c7XG5cblx0ICAgICAgICAgICAgLy8gcmV0dXJuIFg2NFdvcmQuY3JlYXRlKGhpZ2gsIGxvdyk7XG5cdCAgICAgICAgLy8gfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEJpdHdpc2UgWE9ScyB0aGlzIHdvcmQgd2l0aCB0aGUgcGFzc2VkIHdvcmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1g2NFdvcmR9IHdvcmQgVGhlIHg2NC1Xb3JkIHRvIFhPUiB3aXRoIHRoaXMgd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1g2NFdvcmR9IEEgbmV3IHg2NC1Xb3JkIG9iamVjdCBhZnRlciBYT1JpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB4b3JlZCA9IHg2NFdvcmQueG9yKGFub3RoZXJYNjRXb3JkKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICAvLyB4b3I6IGZ1bmN0aW9uICh3b3JkKSB7XG5cdCAgICAgICAgICAgIC8vIHZhciBoaWdoID0gdGhpcy5oaWdoIF4gd29yZC5oaWdoO1xuXHQgICAgICAgICAgICAvLyB2YXIgbG93ID0gdGhpcy5sb3cgXiB3b3JkLmxvdztcblxuXHQgICAgICAgICAgICAvLyByZXR1cm4gWDY0V29yZC5jcmVhdGUoaGlnaCwgbG93KTtcblx0ICAgICAgICAvLyB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogU2hpZnRzIHRoaXMgd29yZCBuIGJpdHMgdG8gdGhlIGxlZnQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0gbiBUaGUgbnVtYmVyIG9mIGJpdHMgdG8gc2hpZnQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtYNjRXb3JkfSBBIG5ldyB4NjQtV29yZCBvYmplY3QgYWZ0ZXIgc2hpZnRpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBzaGlmdGVkID0geDY0V29yZC5zaGlmdEwoMjUpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIC8vIHNoaWZ0TDogZnVuY3Rpb24gKG4pIHtcblx0ICAgICAgICAgICAgLy8gaWYgKG4gPCAzMikge1xuXHQgICAgICAgICAgICAgICAgLy8gdmFyIGhpZ2ggPSAodGhpcy5oaWdoIDw8IG4pIHwgKHRoaXMubG93ID4+PiAoMzIgLSBuKSk7XG5cdCAgICAgICAgICAgICAgICAvLyB2YXIgbG93ID0gdGhpcy5sb3cgPDwgbjtcblx0ICAgICAgICAgICAgLy8gfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIC8vIHZhciBoaWdoID0gdGhpcy5sb3cgPDwgKG4gLSAzMik7XG5cdCAgICAgICAgICAgICAgICAvLyB2YXIgbG93ID0gMDtcblx0ICAgICAgICAgICAgLy8gfVxuXG5cdCAgICAgICAgICAgIC8vIHJldHVybiBYNjRXb3JkLmNyZWF0ZShoaWdoLCBsb3cpO1xuXHQgICAgICAgIC8vIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBTaGlmdHMgdGhpcyB3b3JkIG4gYml0cyB0byB0aGUgcmlnaHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0gbiBUaGUgbnVtYmVyIG9mIGJpdHMgdG8gc2hpZnQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtYNjRXb3JkfSBBIG5ldyB4NjQtV29yZCBvYmplY3QgYWZ0ZXIgc2hpZnRpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBzaGlmdGVkID0geDY0V29yZC5zaGlmdFIoNyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgLy8gc2hpZnRSOiBmdW5jdGlvbiAobikge1xuXHQgICAgICAgICAgICAvLyBpZiAobiA8IDMyKSB7XG5cdCAgICAgICAgICAgICAgICAvLyB2YXIgbG93ID0gKHRoaXMubG93ID4+PiBuKSB8ICh0aGlzLmhpZ2ggPDwgKDMyIC0gbikpO1xuXHQgICAgICAgICAgICAgICAgLy8gdmFyIGhpZ2ggPSB0aGlzLmhpZ2ggPj4+IG47XG5cdCAgICAgICAgICAgIC8vIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICAvLyB2YXIgbG93ID0gdGhpcy5oaWdoID4+PiAobiAtIDMyKTtcblx0ICAgICAgICAgICAgICAgIC8vIHZhciBoaWdoID0gMDtcblx0ICAgICAgICAgICAgLy8gfVxuXG5cdCAgICAgICAgICAgIC8vIHJldHVybiBYNjRXb3JkLmNyZWF0ZShoaWdoLCBsb3cpO1xuXHQgICAgICAgIC8vIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBSb3RhdGVzIHRoaXMgd29yZCBuIGJpdHMgdG8gdGhlIGxlZnQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0gbiBUaGUgbnVtYmVyIG9mIGJpdHMgdG8gcm90YXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7WDY0V29yZH0gQSBuZXcgeDY0LVdvcmQgb2JqZWN0IGFmdGVyIHJvdGF0aW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgcm90YXRlZCA9IHg2NFdvcmQucm90TCgyNSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgLy8gcm90TDogZnVuY3Rpb24gKG4pIHtcblx0ICAgICAgICAgICAgLy8gcmV0dXJuIHRoaXMuc2hpZnRMKG4pLm9yKHRoaXMuc2hpZnRSKDY0IC0gbikpO1xuXHQgICAgICAgIC8vIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBSb3RhdGVzIHRoaXMgd29yZCBuIGJpdHMgdG8gdGhlIHJpZ2h0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHJvdGF0ZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1g2NFdvcmR9IEEgbmV3IHg2NC1Xb3JkIG9iamVjdCBhZnRlciByb3RhdGluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHJvdGF0ZWQgPSB4NjRXb3JkLnJvdFIoNyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgLy8gcm90UjogZnVuY3Rpb24gKG4pIHtcblx0ICAgICAgICAgICAgLy8gcmV0dXJuIHRoaXMuc2hpZnRSKG4pLm9yKHRoaXMuc2hpZnRMKDY0IC0gbikpO1xuXHQgICAgICAgIC8vIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBBZGRzIHRoaXMgd29yZCB3aXRoIHRoZSBwYXNzZWQgd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7WDY0V29yZH0gd29yZCBUaGUgeDY0LVdvcmQgdG8gYWRkIHdpdGggdGhpcyB3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7WDY0V29yZH0gQSBuZXcgeDY0LVdvcmQgb2JqZWN0IGFmdGVyIGFkZGluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGFkZGVkID0geDY0V29yZC5hZGQoYW5vdGhlclg2NFdvcmQpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIC8vIGFkZDogZnVuY3Rpb24gKHdvcmQpIHtcblx0ICAgICAgICAgICAgLy8gdmFyIGxvdyA9ICh0aGlzLmxvdyArIHdvcmQubG93KSB8IDA7XG5cdCAgICAgICAgICAgIC8vIHZhciBjYXJyeSA9IChsb3cgPj4+IDApIDwgKHRoaXMubG93ID4+PiAwKSA/IDEgOiAwO1xuXHQgICAgICAgICAgICAvLyB2YXIgaGlnaCA9ICh0aGlzLmhpZ2ggKyB3b3JkLmhpZ2ggKyBjYXJyeSkgfCAwO1xuXG5cdCAgICAgICAgICAgIC8vIHJldHVybiBYNjRXb3JkLmNyZWF0ZShoaWdoLCBsb3cpO1xuXHQgICAgICAgIC8vIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFuIGFycmF5IG9mIDY0LWJpdCB3b3Jkcy5cblx0ICAgICAqXG5cdCAgICAgKiBAcHJvcGVydHkge0FycmF5fSB3b3JkcyBUaGUgYXJyYXkgb2YgQ3J5cHRvSlMueDY0LldvcmQgb2JqZWN0cy5cblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBzaWdCeXRlcyBUaGUgbnVtYmVyIG9mIHNpZ25pZmljYW50IGJ5dGVzIGluIHRoaXMgd29yZCBhcnJheS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFg2NFdvcmRBcnJheSA9IENfeDY0LldvcmRBcnJheSA9IEJhc2UuZXh0ZW5kKHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7QXJyYXl9IHdvcmRzIChPcHRpb25hbCkgQW4gYXJyYXkgb2YgQ3J5cHRvSlMueDY0LldvcmQgb2JqZWN0cy5cblx0ICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0gc2lnQnl0ZXMgKE9wdGlvbmFsKSBUaGUgbnVtYmVyIG9mIHNpZ25pZmljYW50IGJ5dGVzIGluIHRoZSB3b3Jkcy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLng2NC5Xb3JkQXJyYXkuY3JlYXRlKCk7XG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLng2NC5Xb3JkQXJyYXkuY3JlYXRlKFtcblx0ICAgICAgICAgKiAgICAgICAgIENyeXB0b0pTLng2NC5Xb3JkLmNyZWF0ZSgweDAwMDEwMjAzLCAweDA0MDUwNjA3KSxcblx0ICAgICAgICAgKiAgICAgICAgIENyeXB0b0pTLng2NC5Xb3JkLmNyZWF0ZSgweDE4MTkxYTFiLCAweDFjMWQxZTFmKVxuXHQgICAgICAgICAqICAgICBdKTtcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMueDY0LldvcmRBcnJheS5jcmVhdGUoW1xuXHQgICAgICAgICAqICAgICAgICAgQ3J5cHRvSlMueDY0LldvcmQuY3JlYXRlKDB4MDAwMTAyMDMsIDB4MDQwNTA2MDcpLFxuXHQgICAgICAgICAqICAgICAgICAgQ3J5cHRvSlMueDY0LldvcmQuY3JlYXRlKDB4MTgxOTFhMWIsIDB4MWMxZDFlMWYpXG5cdCAgICAgICAgICogICAgIF0sIDEwKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAod29yZHMsIHNpZ0J5dGVzKSB7XG5cdCAgICAgICAgICAgIHdvcmRzID0gdGhpcy53b3JkcyA9IHdvcmRzIHx8IFtdO1xuXG5cdCAgICAgICAgICAgIGlmIChzaWdCeXRlcyAhPSB1bmRlZmluZWQpIHtcblx0ICAgICAgICAgICAgICAgIHRoaXMuc2lnQnl0ZXMgPSBzaWdCeXRlcztcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIHRoaXMuc2lnQnl0ZXMgPSB3b3Jkcy5sZW5ndGggKiA4O1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIHRoaXMgNjQtYml0IHdvcmQgYXJyYXkgdG8gYSAzMi1iaXQgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0NyeXB0b0pTLmxpYi5Xb3JkQXJyYXl9IFRoaXMgd29yZCBhcnJheSdzIGRhdGEgYXMgYSAzMi1iaXQgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHgzMldvcmRBcnJheSA9IHg2NFdvcmRBcnJheS50b1gzMigpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHRvWDMyOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgeDY0V29yZHMgPSB0aGlzLndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgeDY0V29yZHNMZW5ndGggPSB4NjRXb3Jkcy5sZW5ndGg7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydFxuXHQgICAgICAgICAgICB2YXIgeDMyV29yZHMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB4NjRXb3Jkc0xlbmd0aDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgeDY0V29yZCA9IHg2NFdvcmRzW2ldO1xuXHQgICAgICAgICAgICAgICAgeDMyV29yZHMucHVzaCh4NjRXb3JkLmhpZ2gpO1xuXHQgICAgICAgICAgICAgICAgeDMyV29yZHMucHVzaCh4NjRXb3JkLmxvdyk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gWDMyV29yZEFycmF5LmNyZWF0ZSh4MzJXb3JkcywgdGhpcy5zaWdCeXRlcyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgYSBjb3B5IG9mIHRoaXMgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1g2NFdvcmRBcnJheX0gVGhlIGNsb25lLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2xvbmUgPSB4NjRXb3JkQXJyYXkuY2xvbmUoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBCYXNlLmNsb25lLmNhbGwodGhpcyk7XG5cblx0ICAgICAgICAgICAgLy8gQ2xvbmUgXCJ3b3Jkc1wiIGFycmF5XG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IGNsb25lLndvcmRzID0gdGhpcy53b3Jkcy5zbGljZSgwKTtcblxuXHQgICAgICAgICAgICAvLyBDbG9uZSBlYWNoIFg2NFdvcmQgb2JqZWN0XG5cdCAgICAgICAgICAgIHZhciB3b3Jkc0xlbmd0aCA9IHdvcmRzLmxlbmd0aDtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB3b3Jkc0xlbmd0aDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICB3b3Jkc1tpXSA9IHdvcmRzW2ldLmNsb25lKCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gY2xvbmU7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlM7XG5cbn0pKTsiLCJ2YXIgQ3VybCA9IHJlcXVpcmUoXCIuLi9jdXJsL2N1cmxcIik7XG52YXIgS2VybCA9IHJlcXVpcmUoXCIuLi9rZXJsL2tlcmxcIik7XG52YXIgQ29udmVydGVyID0gcmVxdWlyZShcIi4uL2NvbnZlcnRlci9jb252ZXJ0ZXJcIik7XG52YXIgdHJpdEFkZCA9IHJlcXVpcmUoXCIuLi9oZWxwZXJzL2FkZGVyXCIpO1xuXG4vKipcbipcbiogICBAY29uc3RydWN0b3IgYnVuZGxlXG4qKi9cbmZ1bmN0aW9uIEJ1bmRsZSgpIHtcblxuICAgIC8vIERlY2xhcmUgZW1wdHkgYnVuZGxlXG4gICAgdGhpcy5idW5kbGUgPSBbXTtcbn1cblxuLyoqXG4qXG4qXG4qKi9cblxuQnVuZGxlLnByb3RvdHlwZS5hZGRFbnRyeSA9IGZ1bmN0aW9uKHNpZ25hdHVyZU1lc3NhZ2VMZW5ndGgsIGFkZHJlc3MsIHZhbHVlLCB0YWcsIHRpbWVzdGFtcCwgaW5kZXgpIHtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2lnbmF0dXJlTWVzc2FnZUxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgdmFyIHRyYW5zYWN0aW9uT2JqZWN0ID0gbmV3IE9iamVjdCgpO1xuICAgICAgICB0cmFuc2FjdGlvbk9iamVjdC5hZGRyZXNzID0gYWRkcmVzcztcbiAgICAgICAgdHJhbnNhY3Rpb25PYmplY3QudmFsdWUgPSBpID09IDAgPyB2YWx1ZSA6IDA7XG4gICAgICAgIHRyYW5zYWN0aW9uT2JqZWN0Lm9ic29sZXRlVGFnID0gdGFnO1xuICAgICAgICB0cmFuc2FjdGlvbk9iamVjdC50YWcgPSB0YWc7XG4gICAgICAgIHRyYW5zYWN0aW9uT2JqZWN0LnRpbWVzdGFtcCA9IHRpbWVzdGFtcDtcblxuICAgICAgICB0aGlzLmJ1bmRsZVt0aGlzLmJ1bmRsZS5sZW5ndGhdID0gdHJhbnNhY3Rpb25PYmplY3Q7XG4gICAgfVxufVxuXG4vKipcbipcbipcbioqL1xuQnVuZGxlLnByb3RvdHlwZS5hZGRUcnl0ZXMgPSBmdW5jdGlvbihzaWduYXR1cmVGcmFnbWVudHMpIHtcblxuICAgIHZhciBlbXB0eVNpZ25hdHVyZUZyYWdtZW50ID0gJyc7XG4gICAgdmFyIGVtcHR5SGFzaCA9ICc5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTknO1xuICAgIHZhciBlbXB0eVRhZyA9ICc5Jy5yZXBlYXQoMjcpO1xuICAgIHZhciBlbXB0eVRpbWVzdGFtcCA9ICc5Jy5yZXBlYXQoOSk7XG5cbiAgICBmb3IgKHZhciBqID0gMDsgZW1wdHlTaWduYXR1cmVGcmFnbWVudC5sZW5ndGggPCAyMTg3OyBqKyspIHtcbiAgICAgICAgZW1wdHlTaWduYXR1cmVGcmFnbWVudCArPSAnOSc7XG4gICAgfVxuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0aGlzLmJ1bmRsZS5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIC8vIEZpbGwgZW1wdHkgc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50XG4gICAgICAgIHRoaXMuYnVuZGxlW2ldLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudCA9IHNpZ25hdHVyZUZyYWdtZW50c1tpXSA/IHNpZ25hdHVyZUZyYWdtZW50c1tpXSA6IGVtcHR5U2lnbmF0dXJlRnJhZ21lbnQ7XG5cbiAgICAgICAgLy8gRmlsbCBlbXB0eSB0cnVua1RyYW5zYWN0aW9uXG4gICAgICAgIHRoaXMuYnVuZGxlW2ldLnRydW5rVHJhbnNhY3Rpb24gPSBlbXB0eUhhc2g7XG5cbiAgICAgICAgLy8gRmlsbCBlbXB0eSBicmFuY2hUcmFuc2FjdGlvblxuICAgICAgICB0aGlzLmJ1bmRsZVtpXS5icmFuY2hUcmFuc2FjdGlvbiA9IGVtcHR5SGFzaDtcblxuICAgICAgICB0aGlzLmJ1bmRsZVtpXS5hdHRhY2htZW50VGltZXN0YW1wID0gZW1wdHlUaW1lc3RhbXA7XG4gICAgICAgIHRoaXMuYnVuZGxlW2ldLmF0dGFjaG1lbnRUaW1lc3RhbXBMb3dlckJvdW5kID0gZW1wdHlUaW1lc3RhbXA7XG4gICAgICAgIHRoaXMuYnVuZGxlW2ldLmF0dGFjaG1lbnRUaW1lc3RhbXBVcHBlckJvdW5kID0gZW1wdHlUaW1lc3RhbXA7XG4gICAgICAgIC8vIEZpbGwgZW1wdHkgbm9uY2VcbiAgICAgICAgdGhpcy5idW5kbGVbaV0ubm9uY2UgPSBlbXB0eVRhZztcbiAgICB9XG59XG5cblxuLyoqXG4qXG4qXG4qKi9cbkJ1bmRsZS5wcm90b3R5cGUuZmluYWxpemUgPSBmdW5jdGlvbigpIHtcbiAgICB2YXIgdmFsaWRCdW5kbGUgPSBmYWxzZTtcblxuICB3aGlsZSghdmFsaWRCdW5kbGUpIHtcblxuICAgIHZhciBrZXJsID0gbmV3IEtlcmwoKTtcbiAgICBrZXJsLmluaXRpYWxpemUoKTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5idW5kbGUubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICB2YXIgdmFsdWVUcml0cyA9IENvbnZlcnRlci50cml0cyh0aGlzLmJ1bmRsZVtpXS52YWx1ZSk7XG4gICAgICAgIHdoaWxlICh2YWx1ZVRyaXRzLmxlbmd0aCA8IDgxKSB7XG4gICAgICAgICAgICB2YWx1ZVRyaXRzW3ZhbHVlVHJpdHMubGVuZ3RoXSA9IDA7XG4gICAgICAgIH1cblxuICAgICAgICB2YXIgdGltZXN0YW1wVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModGhpcy5idW5kbGVbaV0udGltZXN0YW1wKTtcbiAgICAgICAgd2hpbGUgKHRpbWVzdGFtcFRyaXRzLmxlbmd0aCA8IDI3KSB7XG4gICAgICAgICAgICB0aW1lc3RhbXBUcml0c1t0aW1lc3RhbXBUcml0cy5sZW5ndGhdID0gMDtcbiAgICAgICAgfVxuXG4gICAgICAgIHZhciBjdXJyZW50SW5kZXhUcml0cyA9IENvbnZlcnRlci50cml0cyh0aGlzLmJ1bmRsZVtpXS5jdXJyZW50SW5kZXggPSBpKTtcbiAgICAgICAgd2hpbGUgKGN1cnJlbnRJbmRleFRyaXRzLmxlbmd0aCA8IDI3KSB7XG4gICAgICAgICAgICBjdXJyZW50SW5kZXhUcml0c1tjdXJyZW50SW5kZXhUcml0cy5sZW5ndGhdID0gMDtcbiAgICAgICAgfVxuXG4gICAgICAgIHZhciBsYXN0SW5kZXhUcml0cyA9IENvbnZlcnRlci50cml0cyh0aGlzLmJ1bmRsZVtpXS5sYXN0SW5kZXggPSB0aGlzLmJ1bmRsZS5sZW5ndGggLSAxKTtcbiAgICAgICAgd2hpbGUgKGxhc3RJbmRleFRyaXRzLmxlbmd0aCA8IDI3KSB7XG4gICAgICAgICAgICBsYXN0SW5kZXhUcml0c1tsYXN0SW5kZXhUcml0cy5sZW5ndGhdID0gMDtcbiAgICAgICAgfVxuXG4gICAgICAgIHZhciBidW5kbGVFc3NlbmNlID0gQ29udmVydGVyLnRyaXRzKHRoaXMuYnVuZGxlW2ldLmFkZHJlc3MgKyBDb252ZXJ0ZXIudHJ5dGVzKHZhbHVlVHJpdHMpICsgdGhpcy5idW5kbGVbaV0ub2Jzb2xldGVUYWcgKyBDb252ZXJ0ZXIudHJ5dGVzKHRpbWVzdGFtcFRyaXRzKSArIENvbnZlcnRlci50cnl0ZXMoY3VycmVudEluZGV4VHJpdHMpICsgQ29udmVydGVyLnRyeXRlcyhsYXN0SW5kZXhUcml0cykpO1xuICAgICAgICBrZXJsLmFic29yYihidW5kbGVFc3NlbmNlLCAwLCBidW5kbGVFc3NlbmNlLmxlbmd0aCk7XG4gICAgfVxuXG4gICAgdmFyIGhhc2ggPSBbXTtcbiAgICBrZXJsLnNxdWVlemUoaGFzaCwgMCwgQ3VybC5IQVNIX0xFTkdUSCk7XG4gICAgaGFzaCA9IENvbnZlcnRlci50cnl0ZXMoaGFzaCk7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRoaXMuYnVuZGxlLmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgdGhpcy5idW5kbGVbaV0uYnVuZGxlID0gaGFzaDtcbiAgICB9XG5cbiAgICB2YXIgbm9ybWFsaXplZEhhc2ggPSB0aGlzLm5vcm1hbGl6ZWRCdW5kbGUoaGFzaCk7XG4gICAgaWYobm9ybWFsaXplZEhhc2guaW5kZXhPZigxMyAvKiA9IE0gKi8pICE9IC0xKSB7XG4gICAgICAvLyBJbnNlY3VyZSBidW5kbGUuIEluY3JlbWVudCBUYWcgYW5kIHJlY29tcHV0ZSBidW5kbGUgaGFzaC5cbiAgICAgIHZhciBpbmNyZWFzZWRUYWcgPSB0cml0QWRkKENvbnZlcnRlci50cml0cyh0aGlzLmJ1bmRsZVswXS5vYnNvbGV0ZVRhZyksIFsxXSk7XG4gICAgICB0aGlzLmJ1bmRsZVswXS5vYnNvbGV0ZVRhZyA9IENvbnZlcnRlci50cnl0ZXMoaW5jcmVhc2VkVGFnKTtcbiAgICB9IGVsc2Uge1xuICAgICAgdmFsaWRCdW5kbGUgPSB0cnVlO1xuICAgIH1cbiAgfVxufVxuXG4vKipcbiogICBOb3JtYWxpemVzIHRoZSBidW5kbGUgaGFzaFxuKlxuKiovXG5CdW5kbGUucHJvdG90eXBlLm5vcm1hbGl6ZWRCdW5kbGUgPSBmdW5jdGlvbihidW5kbGVIYXNoKSB7XG5cbiAgICB2YXIgbm9ybWFsaXplZEJ1bmRsZSA9IFtdO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCAzOyBpKyspIHtcblxuICAgICAgICB2YXIgc3VtID0gMDtcbiAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCAyNzsgaisrKSB7XG5cbiAgICAgICAgICAgIHN1bSArPSAobm9ybWFsaXplZEJ1bmRsZVtpICogMjcgKyBqXSA9IENvbnZlcnRlci52YWx1ZShDb252ZXJ0ZXIudHJpdHMoYnVuZGxlSGFzaC5jaGFyQXQoaSAqIDI3ICsgaikpKSk7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoc3VtID49IDApIHtcblxuICAgICAgICAgICAgd2hpbGUgKHN1bS0tID4gMCkge1xuXG4gICAgICAgICAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCAyNzsgaisrKSB7XG5cbiAgICAgICAgICAgICAgICAgICAgaWYgKG5vcm1hbGl6ZWRCdW5kbGVbaSAqIDI3ICsgal0gPiAtMTMpIHtcblxuICAgICAgICAgICAgICAgICAgICAgICAgbm9ybWFsaXplZEJ1bmRsZVtpICogMjcgKyBqXS0tO1xuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7XG5cbiAgICAgICAgICAgIHdoaWxlIChzdW0rKyA8IDApIHtcblxuICAgICAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMjc7IGorKykge1xuXG4gICAgICAgICAgICAgICAgICAgIGlmIChub3JtYWxpemVkQnVuZGxlW2kgKiAyNyArIGpdIDwgMTMpIHtcblxuICAgICAgICAgICAgICAgICAgICAgICAgbm9ybWFsaXplZEJ1bmRsZVtpICogMjcgKyBqXSsrO1xuICAgICAgICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gbm9ybWFsaXplZEJ1bmRsZTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBCdW5kbGU7XG4iLCIvKipcbiAqXG4gKiAgIENvbnZlcnNpb24gZnVuY3Rpb25zXG4gKlxuICoqL1xuXG52YXIgUkFESVggPSAzO1xudmFyIFJBRElYX0JZVEVTID0gMjU2O1xudmFyIE1BWF9UUklUX1ZBTFVFID0gMTtcbnZhciBNSU5fVFJJVF9WQUxVRSA9IC0xO1xudmFyIEJZVEVfSEFTSF9MRU5HVEggPSA0ODtcblxuLy8gQWxsIHBvc3NpYmxlIHRyeXRlIHZhbHVlc1xudmFyIHRyeXRlc0FscGhhYmV0ID0gXCI5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpcIlxuXG4vLyBtYXAgb2YgYWxsIHRyaXRzIHJlcHJlc2VudGF0aW9uc1xudmFyIHRyeXRlc1RyaXRzID0gW1xuICAgIFsgMCwgIDAsICAwXSxcbiAgICBbIDEsICAwLCAgMF0sXG4gICAgWy0xLCAgMSwgIDBdLFxuICAgIFsgMCwgIDEsICAwXSxcbiAgICBbIDEsICAxLCAgMF0sXG4gICAgWy0xLCAtMSwgIDFdLFxuICAgIFsgMCwgLTEsICAxXSxcbiAgICBbIDEsIC0xLCAgMV0sXG4gICAgWy0xLCAgMCwgIDFdLFxuICAgIFsgMCwgIDAsICAxXSxcbiAgICBbIDEsICAwLCAgMV0sXG4gICAgWy0xLCAgMSwgIDFdLFxuICAgIFsgMCwgIDEsICAxXSxcbiAgICBbIDEsICAxLCAgMV0sXG4gICAgWy0xLCAtMSwgLTFdLFxuICAgIFsgMCwgLTEsIC0xXSxcbiAgICBbIDEsIC0xLCAtMV0sXG4gICAgWy0xLCAgMCwgLTFdLFxuICAgIFsgMCwgIDAsIC0xXSxcbiAgICBbIDEsICAwLCAtMV0sXG4gICAgWy0xLCAgMSwgLTFdLFxuICAgIFsgMCwgIDEsIC0xXSxcbiAgICBbIDEsICAxLCAtMV0sXG4gICAgWy0xLCAtMSwgIDBdLFxuICAgIFsgMCwgLTEsICAwXSxcbiAgICBbIDEsIC0xLCAgMF0sXG4gICAgWy0xLCAgMCwgIDBdXG5dO1xuXG4vKipcbiAqICAgQ29udmVydHMgdHJ5dGVzIGludG8gdHJpdHNcbiAqXG4gKiAgIEBtZXRob2QgdHJpdHNcbiAqICAgQHBhcmFtIHtTdHJpbmd8SW50fSBpbnB1dCBUcnl0ZSB2YWx1ZSB0byBiZSBjb252ZXJ0ZWQuIENhbiBlaXRoZXIgYmUgc3RyaW5nIG9yIGludFxuICogICBAcGFyYW0ge0FycmF5fSBzdGF0ZSAob3B0aW9uYWwpIHN0YXRlIHRvIGJlIG1vZGlmaWVkXG4gKiAgIEByZXR1cm5zIHtBcnJheX0gdHJpdHNcbiAqKi9cbnZhciB0cml0cyA9IGZ1bmN0aW9uKCBpbnB1dCwgc3RhdGUgKSB7XG5cbiAgICB2YXIgdHJpdHMgPSBzdGF0ZSB8fCBbXTtcblxuICAgIGlmIChOdW1iZXIuaXNJbnRlZ2VyKGlucHV0KSkge1xuXG4gICAgICAgIHZhciBhYnNvbHV0ZVZhbHVlID0gaW5wdXQgPCAwID8gLWlucHV0IDogaW5wdXQ7XG5cbiAgICAgICAgd2hpbGUgKGFic29sdXRlVmFsdWUgPiAwKSB7XG5cbiAgICAgICAgICAgIHZhciByZW1haW5kZXIgPSBhYnNvbHV0ZVZhbHVlICUgMztcbiAgICAgICAgICAgIGFic29sdXRlVmFsdWUgPSBNYXRoLmZsb29yKGFic29sdXRlVmFsdWUgLyAzKTtcblxuICAgICAgICAgICAgaWYgKHJlbWFpbmRlciA+IDEpIHtcbiAgICAgICAgICAgICAgICByZW1haW5kZXIgPSAtMTtcbiAgICAgICAgICAgICAgICBhYnNvbHV0ZVZhbHVlKys7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHRyaXRzW3RyaXRzLmxlbmd0aF0gPSByZW1haW5kZXI7XG4gICAgICAgIH1cbiAgICAgICAgaWYgKGlucHV0IDwgMCkge1xuXG4gICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRyaXRzLmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgICAgICAgICB0cml0c1tpXSA9IC10cml0c1tpXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0gZWxzZSB7XG5cbiAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBpbnB1dC5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgICAgICB2YXIgaW5kZXggPSB0cnl0ZXNBbHBoYWJldC5pbmRleE9mKGlucHV0LmNoYXJBdChpKSk7XG4gICAgICAgICAgICB0cml0c1tpICogM10gPSB0cnl0ZXNUcml0c1tpbmRleF1bMF07XG4gICAgICAgICAgICB0cml0c1tpICogMyArIDFdID0gdHJ5dGVzVHJpdHNbaW5kZXhdWzFdO1xuICAgICAgICAgICAgdHJpdHNbaSAqIDMgKyAyXSA9IHRyeXRlc1RyaXRzW2luZGV4XVsyXTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB0cml0cztcbn1cblxuLyoqXG4gKiAgIENvbnZlcnRzIHRyaXRzIGludG8gdHJ5dGVzXG4gKlxuICogICBAbWV0aG9kIHRyeXRlc1xuICogICBAcGFyYW0ge0FycmF5fSB0cml0c1xuICogICBAcmV0dXJucyB7U3RyaW5nfSB0cnl0ZXNcbiAqKi9cbnZhciB0cnl0ZXMgPSBmdW5jdGlvbih0cml0cykge1xuXG4gICAgdmFyIHRyeXRlcyA9IFwiXCI7XG5cbiAgICBmb3IgKCB2YXIgaSA9IDA7IGkgPCB0cml0cy5sZW5ndGg7IGkgKz0gMyApIHtcblxuICAgICAgICAvLyBJdGVyYXRlIG92ZXIgYWxsIHBvc3NpYmxlIHRyeXRlIHZhbHVlcyB0byBmaW5kIGNvcnJlY3QgdHJpdCByZXByZXNlbnRhdGlvblxuICAgICAgICBmb3IgKCB2YXIgaiA9IDA7IGogPCB0cnl0ZXNBbHBoYWJldC5sZW5ndGg7IGorKyApIHtcblxuICAgICAgICAgICAgaWYgKCB0cnl0ZXNUcml0c1sgaiBdWyAwIF0gPT09IHRyaXRzWyBpIF0gJiYgdHJ5dGVzVHJpdHNbIGogXVsgMSBdID09PSB0cml0c1sgaSArIDEgXSAmJiB0cnl0ZXNUcml0c1sgaiBdWyAyIF0gPT09IHRyaXRzWyBpICsgMiBdICkge1xuXG4gICAgICAgICAgICAgICAgdHJ5dGVzICs9IHRyeXRlc0FscGhhYmV0LmNoYXJBdCggaiApO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgfVxuXG4gICAgfVxuXG4gICAgcmV0dXJuIHRyeXRlcztcbn1cblxuLyoqXG4gKiAgIENvbnZlcnRzIHRyaXRzIGludG8gYW4gaW50ZWdlciB2YWx1ZVxuICpcbiAqICAgQG1ldGhvZCB2YWx1ZVxuICogICBAcGFyYW0ge0FycmF5fSB0cml0c1xuICogICBAcmV0dXJucyB7aW50fSB2YWx1ZVxuICoqL1xudmFyIHZhbHVlID0gZnVuY3Rpb24odHJpdHMpIHtcblxuICAgIHZhciByZXR1cm5WYWx1ZSA9IDA7XG5cbiAgICBmb3IgKCB2YXIgaSA9IHRyaXRzLmxlbmd0aDsgaS0tID4gMDsgKSB7XG5cbiAgICAgICAgcmV0dXJuVmFsdWUgPSByZXR1cm5WYWx1ZSAqIDMgKyB0cml0c1sgaSBdO1xuICAgIH1cblxuICAgIHJldHVybiByZXR1cm5WYWx1ZTtcbn1cblxuLyoqXG4gKiAgIENvbnZlcnRzIGFuIGludGVnZXIgdmFsdWUgdG8gdHJpdHNcbiAqXG4gKiAgIEBtZXRob2QgdmFsdWVcbiAqICAgQHBhcmFtIHtJbnR9IHZhbHVlXG4gKiAgIEByZXR1cm5zIHtBcnJheX0gdHJpdHNcbiAqKi9cbnZhciBmcm9tVmFsdWUgPSBmdW5jdGlvbih2YWx1ZSkge1xuXG4gICAgdmFyIGRlc3RpbmF0aW9uID0gW107XG4gICAgdmFyIGFic29sdXRlVmFsdWUgPSB2YWx1ZSA8IDAgPyAtdmFsdWUgOiB2YWx1ZTtcbiAgICB2YXIgaSA9IDA7XG5cbiAgICB3aGlsZSggYWJzb2x1dGVWYWx1ZSA+IDAgKSB7XG5cbiAgICAgICAgdmFyIHJlbWFpbmRlciA9ICggYWJzb2x1dGVWYWx1ZSAlIFJBRElYICk7XG4gICAgICAgIGFic29sdXRlVmFsdWUgPSBNYXRoLmZsb29yKCBhYnNvbHV0ZVZhbHVlIC8gUkFESVggKTtcblxuICAgICAgICBpZiAoIHJlbWFpbmRlciA+IE1BWF9UUklUX1ZBTFVFICkge1xuXG4gICAgICAgICAgICByZW1haW5kZXIgPSBNSU5fVFJJVF9WQUxVRTtcbiAgICAgICAgICAgIGFic29sdXRlVmFsdWUrKztcblxuICAgICAgICB9XG5cbiAgICAgICAgZGVzdGluYXRpb25bIGkgXSA9IHJlbWFpbmRlcjtcbiAgICAgICAgaSsrO1xuXG4gICAgfVxuXG4gICAgaWYgKCB2YWx1ZSA8IDAgKSB7XG5cbiAgICAgICAgZm9yICggdmFyIGogPSAwOyBqIDwgZGVzdGluYXRpb24ubGVuZ3RoOyBqKysgKSB7XG5cbiAgICAgICAgICAgIC8vIHN3aXRjaCB2YWx1ZXNcbiAgICAgICAgICAgIGRlc3RpbmF0aW9uWyBqIF0gPSBkZXN0aW5hdGlvblsgaiBdID09PSAwID8gMDogLWRlc3RpbmF0aW9uWyBqIF07XG5cbiAgICAgICAgfVxuXG4gICAgfVxuXG4gICAgcmV0dXJuIGRlc3RpbmF0aW9uO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgICB0cml0cyAgICAgICAgICAgOiB0cml0cyxcbiAgICB0cnl0ZXMgICAgICAgICAgOiB0cnl0ZXMsXG4gICAgdmFsdWUgICAgICAgICAgIDogdmFsdWUsXG4gICAgZnJvbVZhbHVlICAgICAgIDogZnJvbVZhbHVlXG59O1xuIiwidmFyIElOVF9MRU5HVEggPSAxMjtcbnZhciBCWVRFX0xFTkdUSCA9IDQ4O1xudmFyIFJBRElYID0gMztcbi8vLyBoZXggcmVwcmVzZW50YXRpb24gb2YgKDNeMjQyKS8yXG52YXIgSEFMRl8zID0gbmV3IFVpbnQzMkFycmF5KFtcbiAgICAweGE1Y2U4OTY0LFxuICAgIDB4OWYwMDc2NjksXG4gICAgMHgxNDg0NTA0ZixcbiAgICAweDNhZGUwMGQ5LFxuICAgIDB4MGMyNDQ4NmUsXG4gICAgMHg1MDk3OWQ1NyxcbiAgICAweDc5YTRjNzAyLFxuICAgIDB4NDhiYmFlMzYsXG4gICAgMHhhOWY2ODA4YixcbiAgICAweGFhMDZhODA1LFxuICAgIDB4YTg3ZmFiZGYsXG4gICAgMHg1ZTY5ZWJlZlxuXSk7XG5cbnZhciBjbG9uZV91aW50MzJBcnJheSA9IGZ1bmN0aW9uKHNvdXJjZUFycmF5KSB7XG4gIHZhciBkZXN0aW5hdGlvbiA9IG5ldyBBcnJheUJ1ZmZlcihzb3VyY2VBcnJheS5ieXRlTGVuZ3RoKTtcbiAgbmV3IFVpbnQzMkFycmF5KGRlc3RpbmF0aW9uKS5zZXQobmV3IFVpbnQzMkFycmF5KHNvdXJjZUFycmF5KSk7XG5cbiAgcmV0dXJuIGRlc3RpbmF0aW9uO1xufTtcblxudmFyIHRhX3NsaWNlID0gZnVuY3Rpb24oYXJyYXkpIHtcbiAgaWYgKGFycmF5LnNsaWNlICE9PSB1bmRlZmluZWQpIHtcbiAgICAgIHJldHVybiBhcnJheS5zbGljZSgpO1xuICB9XG5cbiAgcmV0dXJuIGNsb25lX3VpbnQzMkFycmF5KGFycmF5KTtcbn07XG5cbnZhciB0YV9yZXZlcnNlID0gZnVuY3Rpb24oYXJyYXkpIHtcbiAgaWYgKGFycmF5LnJldmVyc2UgIT09IHVuZGVmaW5lZCkge1xuICAgIGFycmF5LnJldmVyc2UoKTtcbiAgICByZXR1cm47XG4gIH1cblxuICB2YXIgaSA9IDAsXG4gICAgbiA9IGFycmF5Lmxlbmd0aCxcbiAgICBtaWRkbGUgPSBNYXRoLmZsb29yKG4gLyAyKSxcbiAgICB0ZW1wID0gbnVsbDtcblxuICBmb3IgKDsgaSA8IG1pZGRsZTsgaSArPSAxKSB7XG4gICAgdGVtcCA9IGFycmF5W2ldO1xuICAgIGFycmF5W2ldID0gYXJyYXlbbiAtIDEgLSBpXTtcbiAgICBhcnJheVtuIC0gMSAtIGldID0gdGVtcDtcbiAgfVxufTtcblxuLy8vIG5lZ2F0ZXMgdGhlICh1bnNpZ25lZCkgaW5wdXQgYXJyYXlcbnZhciBiaWdpbnRfbm90ID0gZnVuY3Rpb24oYXJyKSB7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcnIubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYXJyW2ldID0gKH5hcnJbaV0pID4+PiAwO1xuICAgIH1cbn07XG5cbi8vLyByc2hpZnQgdGhhdCB3b3JrcyB3aXRoIHVwIHRvIDUzXG4vLy8gSlMncyBzaGlmdCBvcGVyYXRvcnMgb25seSB3b3JrIG9uIDMyIGJpdCBpbnRlZ2Vyc1xuLy8vIG91cnMgaXMgdXAgdG8gMzMgb3IgMzQgYml0cyB0aG91Z2gsIHNvXG4vLy8gd2UgbmVlZCB0byBpbXBsZW1lbnQgc2hpZnRpbmcgbWFudWFsbHlcbnZhciByc2hpZnQgPSBmdW5jdGlvbihudW1iZXIsIHNoaWZ0KSB7XG4gICAgcmV0dXJuIChudW1iZXIgLyBNYXRoLnBvdygyLCBzaGlmdCkpID4+PiAwO1xufTtcblxuLy8vIHN3YXBzIGVuZGlhbm5lc3NcbnZhciBzd2FwMzIgPSBmdW5jdGlvbih2YWwpIHtcbiAgICByZXR1cm4gKCh2YWwgJiAweEZGKSA8PCAyNCkgfFxuICAgICAgICAoKHZhbCAmIDB4RkYwMCkgPDwgOCkgfFxuICAgICAgICAoKHZhbCA+PiA4KSAmIDB4RkYwMCkgfFxuICAgICAgICAoKHZhbCA+PiAyNCkgJiAweEZGKTtcbn1cblxuLy8vIGFkZCB3aXRoIGNhcnJ5XG52YXIgZnVsbF9hZGQgPSBmdW5jdGlvbihsaCwgcmgsIGNhcnJ5KSB7XG4gICAgdmFyIHYgPSBsaCArIHJoO1xuICAgIHZhciBsID0gKHJzaGlmdCh2LCAzMikpICYgMHhGRkZGRkZGRjtcbiAgICB2YXIgciA9ICh2ICYgMHhGRkZGRkZGRikgPj4+IDA7XG4gICAgdmFyIGNhcnJ5MSA9IGwgIT0gMDtcblxuICAgIGlmIChjYXJyeSkge1xuICAgICAgICB2ID0gciArIDE7XG4gICAgfVxuICAgIGwgPSAocnNoaWZ0KHYsIDMyKSkgJiAweEZGRkZGRkZGO1xuICAgIHIgPSAodiAmIDB4RkZGRkZGRkYpID4+PiAwO1xuICAgIHZhciBjYXJyeTIgPSBsICE9IDA7XG5cbiAgICByZXR1cm4gW3IsIGNhcnJ5MSB8fCBjYXJyeTJdO1xufTtcblxuLy8vIHN1YnRyYWN0cyByaCBmcm9tIGJhc2VcbnZhciBiaWdpbnRfc3ViID0gZnVuY3Rpb24oYmFzZSwgcmgpIHtcbiAgICB2YXIgbm9ib3Jyb3cgPSB0cnVlO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBiYXNlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHZhciB2YyA9IGZ1bGxfYWRkKGJhc2VbaV0sICh+cmhbaV0gPj4+IDApLCBub2JvcnJvdyk7XG4gICAgICAgIGJhc2VbaV0gPSB2Y1swXTtcbiAgICAgICAgbm9ib3Jyb3cgPSB2Y1sxXTtcbiAgICB9XG5cbiAgICBpZiAoIW5vYm9ycm93KSB7XG4gICAgICAgIHRocm93IFwibm9ib3Jyb3dcIjtcbiAgICB9XG59O1xuXG4vLy8gY29tcGFyZXMgdHdvICh1bnNpZ25lZCkgYmlnIGludGVnZXJzXG52YXIgYmlnaW50X2NtcCA9IGZ1bmN0aW9uKGxoLCByaCkge1xuICAgIGZvciAodmFyIGkgPSBsaC5sZW5ndGg7IGktLSA+IDA7KSB7XG4gICAgICAgIHZhciBhID0gbGhbaV0gPj4+IDA7XG4gICAgICAgIHZhciBiID0gcmhbaV0gPj4+IDA7XG4gICAgICAgIGlmIChhIDwgYikge1xuICAgICAgICAgICAgcmV0dXJuIC0xO1xuICAgICAgICB9IGVsc2UgaWYgKGEgPiBiKSB7XG4gICAgICAgICAgICByZXR1cm4gMTtcbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4gMDtcbn07XG5cbi8vLyBhZGRzIHJoIHRvIGJhc2UgaW4gcGxhY2VcbnZhciBiaWdpbnRfYWRkID0gZnVuY3Rpb24oYmFzZSwgcmgpIHtcbiAgICB2YXIgY2FycnkgPSBmYWxzZTtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJhc2UubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgdmFyIHZjID0gZnVsbF9hZGQoYmFzZVtpXSwgcmhbaV0sIGNhcnJ5KTtcbiAgICAgICAgYmFzZVtpXSA9IHZjWzBdO1xuICAgICAgICBjYXJyeSA9IHZjWzFdO1xuICAgIH1cbn07XG5cbi8vLyBhZGRzIGEgc21hbGwgKGkuZS4gPDMyYml0KSBudW1iZXIgdG8gYmFzZVxudmFyIGJpZ2ludF9hZGRfc21hbGwgPSBmdW5jdGlvbihiYXNlLCBvdGhlcikge1xuICAgIHZhciB2YyA9IGZ1bGxfYWRkKGJhc2VbMF0sIG90aGVyLCBmYWxzZSk7XG4gICAgYmFzZVswXSA9IHZjWzBdO1xuICAgIHZhciBjYXJyeSA9IHZjWzFdO1xuXG4gICAgdmFyIGkgPSAxO1xuICAgIHdoaWxlIChjYXJyeSAmJiBpIDwgYmFzZS5sZW5ndGgpIHtcbiAgICAgICAgdmFyIHZjID0gZnVsbF9hZGQoYmFzZVtpXSwgMCwgY2FycnkpO1xuICAgICAgICBiYXNlW2ldID0gdmNbMF07XG4gICAgICAgIGNhcnJ5ID0gdmNbMV07XG4gICAgICAgIGkgKz0gMTtcbiAgICB9XG5cbiAgICByZXR1cm4gaTtcbn07XG5cbi8vLyBjb252ZXJ0cyB0aGUgZ2l2ZW4gYnl0ZSBhcnJheSB0byB0cml0c1xudmFyIHdvcmRzX3RvX3RyaXRzID0gZnVuY3Rpb24od29yZHMpIHtcbiAgICBpZiAod29yZHMubGVuZ3RoICE9IElOVF9MRU5HVEgpIHtcbiAgICAgICAgdGhyb3cgXCJJbnZhbGlkIHdvcmRzIGxlbmd0aFwiO1xuICAgIH1cblxuICAgIHZhciB0cml0cyA9IG5ldyBJbnQ4QXJyYXkoMjQzKTtcbiAgICB2YXIgYmFzZSA9IG5ldyBVaW50MzJBcnJheSh3b3Jkcyk7XG5cbiAgICB0YV9yZXZlcnNlKGJhc2UpO1xuXG4gICAgdmFyIGZsaXBfdHJpdHMgPSBmYWxzZTtcbiAgICBpZiAoYmFzZVtJTlRfTEVOR1RIIC0gMV0gPj4gMzEgPT0gMCkge1xuICAgICAgICAvLyBwb3NpdGl2ZSB0d28ncyBjb21wbGVtZW50IG51bWJlci5cbiAgICAgICAgLy8gYWRkIEhBTEZfMyB0byBtb3ZlIGl0IHRvIHRoZSByaWdodCBwbGFjZS5cbiAgICAgICAgYmlnaW50X2FkZChiYXNlLCBIQUxGXzMpO1xuICAgIH0gZWxzZSB7XG4gICAgICAgIC8vIG5lZ2F0aXZlIG51bWJlci5cbiAgICAgICAgYmlnaW50X25vdChiYXNlKTtcbiAgICAgICAgaWYgKGJpZ2ludF9jbXAoYmFzZSwgSEFMRl8zKSA+IDApIHtcbiAgICAgICAgICAgIGJpZ2ludF9zdWIoYmFzZSwgSEFMRl8zKTtcbiAgICAgICAgICAgIGZsaXBfdHJpdHMgPSB0cnVlO1xuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy8vIGJpZ2ludCBpcyBiZXR3ZWVuICh1bnNpZ25lZCkgSEFMRl8zIGFuZCAoMioqMzg0IC0gMyoqMjQyLzIpLlxuICAgICAgICAgICAgYmlnaW50X2FkZF9zbWFsbChiYXNlLCAxKTtcbiAgICAgICAgICAgIHZhciB0bXAgPSB0YV9zbGljZShIQUxGXzMpO1xuICAgICAgICAgICAgYmlnaW50X3N1Yih0bXAsIGJhc2UpO1xuICAgICAgICAgICAgYmFzZSA9IHRtcDtcbiAgICAgICAgfVxuICAgIH1cblxuXG4gICAgdmFyIHJlbSA9IDA7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI0MjsgaSsrKSB7XG4gICAgICAgIHJlbSA9IDA7XG4gICAgICAgIGZvciAodmFyIGogPSBJTlRfTEVOR1RIIC0gMTsgaiA+PSAwOyBqLS0pIHtcbiAgICAgICAgICAgIHZhciBsaHMgPSAocmVtICE9IDAgPyByZW0gKiAweEZGRkZGRkZGICsgcmVtIDogMCkgKyBiYXNlW2pdO1xuICAgICAgICAgICAgdmFyIHJocyA9IFJBRElYO1xuXG4gICAgICAgICAgICB2YXIgcSA9IChsaHMgLyByaHMpID4+PiAwO1xuICAgICAgICAgICAgdmFyIHIgPSAobGhzICUgcmhzKSA+Pj4gMDtcblxuICAgICAgICAgICAgYmFzZVtqXSA9IHE7XG4gICAgICAgICAgICByZW0gPSByO1xuICAgICAgICB9XG5cbiAgICAgICAgdHJpdHNbaV0gPSByZW0gLSAxO1xuICAgIH1cblxuICAgIGlmIChmbGlwX3RyaXRzKSB7XG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdHJpdHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIHRyaXRzW2ldID0gLXRyaXRzW2ldO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHRyaXRzO1xufVxuXG52YXIgaXNfbnVsbCA9IGZ1bmN0aW9uKGFycikge1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJyLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGlmIChhcnJbaV0gIT0gMCkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIHRydWU7XG59XG5cbnZhciB0cml0c190b193b3JkcyA9IGZ1bmN0aW9uKHRyaXRzKSB7XG4gICAgaWYgKHRyaXRzLmxlbmd0aCAhPSAyNDMpIHtcbiAgICAgICAgdGhyb3cgXCJJbnZhbGlkIHRyaXRzIGxlbmd0aFwiO1xuICAgIH1cblxuICAgIHZhciBiYXNlID0gbmV3IFVpbnQzMkFycmF5KElOVF9MRU5HVEgpO1xuXG4gICAgaWYgKHRyaXRzLnNsaWNlKDAsIDI0MikuZXZlcnkoZnVuY3Rpb24oYSkge1xuICAgICAgICAgICAgYSA9PSAtMVxuICAgICAgICB9KSkge1xuICAgICAgICBiYXNlID0gdGFfc2xpY2UoSEFMRl8zKTtcbiAgICAgICAgYmlnaW50X25vdChiYXNlKTtcbiAgICAgICAgYmlnaW50X2FkZF9zbWFsbChiYXNlLCAxKTtcbiAgICB9IGVsc2Uge1xuICAgICAgICB2YXIgc2l6ZSA9IDE7XG4gICAgICAgIGZvciAodmFyIGkgPSB0cml0cy5sZW5ndGggLSAxOyBpLS0gPiAwOykge1xuICAgICAgICAgICAgdmFyIHRyaXQgPSB0cml0c1tpXSArIDE7XG5cbiAgICAgICAgICAgIC8vbXVsdGlwbHkgYnkgcmFkaXhcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgc3ogPSBzaXplO1xuICAgICAgICAgICAgICAgIHZhciBjYXJyeSA9IDA7XG5cbiAgICAgICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IHN6OyBqKyspIHtcbiAgICAgICAgICAgICAgICAgICAgdmFyIHYgPSBiYXNlW2pdICogUkFESVggKyBjYXJyeTtcbiAgICAgICAgICAgICAgICAgICAgY2FycnkgPSByc2hpZnQodiwgMzIpO1xuICAgICAgICAgICAgICAgICAgICBiYXNlW2pdID0gKHYgJiAweEZGRkZGRkZGKSA+Pj4gMDtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBpZiAoY2FycnkgPiAwKSB7XG4gICAgICAgICAgICAgICAgICAgIGJhc2Vbc3pdID0gY2Fycnk7XG4gICAgICAgICAgICAgICAgICAgIHNpemUgKz0gMTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vYWRkaXRpb25cbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICB2YXIgc3ogPSBiaWdpbnRfYWRkX3NtYWxsKGJhc2UsIHRyaXQpO1xuICAgICAgICAgICAgICAgIGlmIChzeiA+IHNpemUpIHtcbiAgICAgICAgICAgICAgICAgICAgc2l6ZSA9IHN6O1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghaXNfbnVsbChiYXNlKSkge1xuICAgICAgICAgICAgaWYgKGJpZ2ludF9jbXAoSEFMRl8zLCBiYXNlKSA8PSAwKSB7XG4gICAgICAgICAgICAgICAgLy8gYmFzZSA+PSBIQUxGXzNcbiAgICAgICAgICAgICAgICAvLyBqdXN0IGRvIGJhc2UgLSBIQUxGXzNcbiAgICAgICAgICAgICAgICBiaWdpbnRfc3ViKGJhc2UsIEhBTEZfMyk7XG4gICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgIC8vIGJhc2UgPCBIQUxGXzNcbiAgICAgICAgICAgICAgICAvLyBzbyB3ZSBuZWVkIHRvIHRyYW5zZm9ybSBpdCB0byBhIHR3bydzIGNvbXBsZW1lbnQgcmVwcmVzZW50YXRpb25cbiAgICAgICAgICAgICAgICAvLyBvZiAoYmFzZSAtIEhBTEZfMykuXG4gICAgICAgICAgICAgICAgLy8gYXMgd2UgZG9uJ3QgaGF2ZSBhIHdyYXBwaW5nICgtKSwgd2UgbmVlZCB0byB1c2Ugc29tZSBiaXQgbWFnaWNcbiAgICAgICAgICAgICAgICB2YXIgdG1wID0gdGFfc2xpY2UoSEFMRl8zKTtcbiAgICAgICAgICAgICAgICBiaWdpbnRfc3ViKHRtcCwgYmFzZSk7XG4gICAgICAgICAgICAgICAgYmlnaW50X25vdCh0bXApO1xuICAgICAgICAgICAgICAgIGJpZ2ludF9hZGRfc21hbGwodG1wLCAxKTtcbiAgICAgICAgICAgICAgICBiYXNlID0gdG1wO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgdGFfcmV2ZXJzZShiYXNlKTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYmFzZS5sZW5ndGg7IGkrKykge1xuICAgICAgICBiYXNlW2ldID0gc3dhcDMyKGJhc2VbaV0pO1xuICAgIH1cblxuICAgIHJldHVybiBiYXNlO1xufTtcblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gICAgdHJpdHNfdG9fd29yZHM6IHRyaXRzX3RvX3dvcmRzLFxuICAgIHdvcmRzX3RvX3RyaXRzOiB3b3Jkc190b190cml0c1xufTtcbiIsInZhciBDb252ZXJ0ZXIgPSByZXF1aXJlKFwiLi4vY29udmVydGVyL2NvbnZlcnRlclwiKTtcblxuLyoqXG4qKiAgICAgIENyeXB0b2dyYXBoaWMgcmVsYXRlZCBmdW5jdGlvbnMgdG8gSU9UQSdzIEN1cmwgKHNwb25nZSBmdW5jdGlvbilcbioqL1xuXG52YXIgTlVNQkVSX09GX1JPVU5EUyA9IDgxO1xudmFyIEhBU0hfTEVOR1RIID0gMjQzO1xudmFyIFNUQVRFX0xFTkdUSCA9IDMgKiBIQVNIX0xFTkdUSDtcblxuZnVuY3Rpb24gQ3VybChyb3VuZHMpIHtcbiAgICBpZiAocm91bmRzKSB7XG4gICAgICB0aGlzLnJvdW5kcyA9IHJvdW5kcztcbiAgICB9IGVsc2Uge1xuICAgICAgdGhpcy5yb3VuZHMgPSBOVU1CRVJfT0ZfUk9VTkRTO1xuICAgIH1cbiAgICAvLyB0cnV0aCB0YWJsZVxuICAgIHRoaXMudHJ1dGhUYWJsZSA9IFsxLCAwLCAtMSwgMiwgMSwgLTEsIDAsIDIsIC0xLCAxLCAwXTtcbn1cblxuQ3VybC5IQVNIX0xFTkdUSCA9IEhBU0hfTEVOR1RIO1xuXG4vKipcbiogICBJbml0aWFsaXplcyB0aGUgc3RhdGUgd2l0aCBTVEFURV9MRU5HVEggdHJpdHNcbipcbiogICBAbWV0aG9kIGluaXRpYWxpemVcbioqL1xuQ3VybC5wcm90b3R5cGUuaW5pdGlhbGl6ZSA9IGZ1bmN0aW9uKHN0YXRlLCBsZW5ndGgpIHtcblxuICAgIGlmIChzdGF0ZSkge1xuXG4gICAgICAgIHRoaXMuc3RhdGUgPSBzdGF0ZTtcblxuICAgIH0gZWxzZSB7XG5cbiAgICAgICAgdGhpcy5zdGF0ZSA9IFtdO1xuXG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgU1RBVEVfTEVOR1RIOyBpKyspIHtcblxuICAgICAgICAgICAgdGhpcy5zdGF0ZVtpXSA9IDA7XG5cbiAgICAgICAgfVxuICAgIH1cbn1cblxuQ3VybC5wcm90b3R5cGUucmVzZXQgPSBmdW5jdGlvbigpIHtcbiAgdGhpcy5pbml0aWFsaXplKCk7XG59XG5cbi8qKlxuKiAgIFNwb25nZSBhYnNvcmIgZnVuY3Rpb25cbipcbiogICBAbWV0aG9kIGFic29yYlxuKiovXG5DdXJsLnByb3RvdHlwZS5hYnNvcmIgPSBmdW5jdGlvbih0cml0cywgb2Zmc2V0LCBsZW5ndGgpIHtcblxuICAgIGRvIHtcblxuICAgICAgICB2YXIgaSA9IDA7XG4gICAgICAgIHZhciBsaW1pdCA9IChsZW5ndGggPCBIQVNIX0xFTkdUSCA/IGxlbmd0aCA6IEhBU0hfTEVOR1RIKTtcblxuICAgICAgICB3aGlsZSAoaSA8IGxpbWl0KSB7XG5cbiAgICAgICAgICAgIHRoaXMuc3RhdGVbaSsrXSA9IHRyaXRzW29mZnNldCsrXTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMudHJhbnNmb3JtKCk7XG5cbiAgICB9IHdoaWxlICgoIGxlbmd0aCAtPSBIQVNIX0xFTkdUSCApID4gMClcblxufVxuXG4vKipcbiogICBTcG9uZ2Ugc3F1ZWV6ZSBmdW5jdGlvblxuKlxuKiAgIEBtZXRob2Qgc3F1ZWV6ZVxuKiovXG5DdXJsLnByb3RvdHlwZS5zcXVlZXplID0gZnVuY3Rpb24odHJpdHMsIG9mZnNldCwgbGVuZ3RoKSB7XG5cbiAgICBkbyB7XG5cbiAgICAgICAgdmFyIGkgPSAwO1xuICAgICAgICB2YXIgbGltaXQgPSAobGVuZ3RoIDwgSEFTSF9MRU5HVEggPyBsZW5ndGggOiBIQVNIX0xFTkdUSCk7XG5cbiAgICAgICAgd2hpbGUgKGkgPCBsaW1pdCkge1xuXG4gICAgICAgICAgICB0cml0c1tvZmZzZXQrK10gPSB0aGlzLnN0YXRlW2krK107XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLnRyYW5zZm9ybSgpO1xuXG4gICAgfSB3aGlsZSAoKCBsZW5ndGggLT0gSEFTSF9MRU5HVEggKSA+IDApXG59XG5cbi8qKlxuKiAgIFNwb25nZSB0cmFuc2Zvcm0gZnVuY3Rpb25cbipcbiogICBAbWV0aG9kIHRyYW5zZm9ybVxuKiovXG5DdXJsLnByb3RvdHlwZS50cmFuc2Zvcm0gPSBmdW5jdGlvbigpIHtcblxuICAgIHZhciBzdGF0ZUNvcHkgPSBbXSwgaW5kZXggPSAwO1xuXG4gICAgZm9yICh2YXIgcm91bmQgPSAwOyByb3VuZCA8IHRoaXMucm91bmRzOyByb3VuZCsrKSB7XG5cbiAgICAgICAgc3RhdGVDb3B5ID0gdGhpcy5zdGF0ZS5zbGljZSgpO1xuXG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgU1RBVEVfTEVOR1RIOyBpKyspIHtcblxuICAgICAgICAgICAgdGhpcy5zdGF0ZVtpXSA9IHRoaXMudHJ1dGhUYWJsZVtzdGF0ZUNvcHlbaW5kZXhdICsgKHN0YXRlQ29weVtpbmRleCArPSAoaW5kZXggPCAzNjUgPyAzNjQgOiAtMzY1KV0gPDwgMikgKyA1XTtcbiAgICAgICAgfVxuICAgIH1cbn1cblxubW9kdWxlLmV4cG9ydHMgPSBDdXJsXG4iLCIvKiBjb3B5cmlnaHQgUGF1bCBIYW5keSwgMjAxNyAqL1xuXG5mdW5jdGlvbiBzdW0oIGEsIGIgKSB7XG5cbiAgICB2YXIgcyA9IGEgKyBiO1xuXG4gICAgc3dpdGNoKCBzICkge1xuXG4gICAgICAgIGNhc2UgMjogcmV0dXJuIC0xO1xuICAgICAgICBjYXNlIC0yOiByZXR1cm4gMTtcbiAgICAgICAgZGVmYXVsdDogcmV0dXJuIHM7XG5cbiAgICB9XG59XG5cbmZ1bmN0aW9uIGNvbnMoIGEsIGIgKSB7XG5cbiAgICBpZiggYSA9PT0gYiApIHtcblxuICAgICAgICByZXR1cm4gYTtcblxuICAgIH1cblxuICAgIHJldHVybiAwO1xufVxuXG5mdW5jdGlvbiBhbnkoIGEsIGIgKSB7XG5cbiAgICB2YXIgcyA9IGEgKyBiO1xuXG4gICAgaWYgKCBzID4gMCApIHtcblxuICAgICAgICByZXR1cm4gMTtcblxuICAgIH0gZWxzZSBpZiAoIHMgPCAwICkge1xuXG4gICAgICAgIHJldHVybiAtMTtcblxuICAgIH1cblxuICAgIHJldHVybiAwO1xufVxuXG5mdW5jdGlvbiBmdWxsX2FkZCggYSwgYiwgYyApIHtcblxuICAgIHZhciBzX2EgICAgID0gICBzdW0oIGEsIGIgKTtcbiAgICB2YXIgY19hICAgICA9ICAgY29ucyggYSwgYiApO1xuICAgIHZhciBjX2IgICAgID0gICBjb25zKCBzX2EsIGMgKTtcbiAgICB2YXIgY19vdXQgICA9ICAgYW55KCBjX2EsIGNfYiApO1xuICAgIHZhciBzX291dCAgID0gICBzdW0oIHNfYSwgYyApO1xuXG4gICAgcmV0dXJuIFsgc19vdXQsIGNfb3V0IF07XG5cbn1cblxuZnVuY3Rpb24gYWRkKCBhLCBiICkge1xuXG4gICAgdmFyIG91dCA9IG5ldyBBcnJheSggTWF0aC5tYXgoIGEubGVuZ3RoLCBiLmxlbmd0aCApICk7XG4gICAgdmFyIGNhcnJ5ID0gMDtcbiAgICB2YXIgYV9pLCBiX2k7XG5cbiAgICBmb3IoIHZhciBpID0gMDsgaSA8IG91dC5sZW5ndGg7IGkrKyApIHtcblxuICAgICAgICBhX2kgPSBpIDwgYS5sZW5ndGggPyBhWyBpIF0gOiAwO1xuICAgICAgICBiX2kgPSBpIDwgYi5sZW5ndGggPyBiWyBpIF0gOiAwO1xuICAgICAgICB2YXIgZl9hID0gZnVsbF9hZGQoIGFfaSwgYl9pLCBjYXJyeSApO1xuICAgICAgICBvdXRbIGkgXSA9IGZfYVsgMCBdO1xuICAgICAgICBjYXJyeSA9IGZfYVsgMSBdO1xuXG4gICAgfVxuXG4gICAgcmV0dXJuIG91dDtcblxufVxuXG5tb2R1bGUuZXhwb3J0cyA9IGFkZDtcbiIsInZhciBDdXJsID0gcmVxdWlyZShcIi4uL2N1cmwvY3VybFwiKTtcbnZhciBDb252ZXJ0ZXIgPSByZXF1aXJlKFwiLi4vY29udmVydGVyL2NvbnZlcnRlclwiKTtcbnZhciBITUFDX1JPVU5EUyA9IDI3O1xuXG5mdW5jdGlvbiBobWFjKGtleSkge1xuICAgIHRoaXMuX2tleSA9IENvbnZlcnRlci50cml0cyhrZXkpO1xufVxuXG5obWFjLnByb3RvdHlwZS5hZGRITUFDID0gZnVuY3Rpb24oYnVuZGxlKSB7XG4gICAgdmFyIGN1cmwgPSBuZXcgQ3VybChITUFDX1JPVU5EUyk7XG4gICAgdmFyIGtleSA9IHRoaXMuX2tleTtcbiAgICBmb3IodmFyIGkgPSAwOyBpIDwgYnVuZGxlLmJ1bmRsZS5sZW5ndGg7IGkrKykge1xuICAgICAgICBpZiAoYnVuZGxlLmJ1bmRsZVtpXS52YWx1ZSA+IDApIHtcbiAgICAgICAgICAgIHZhciBidW5kbGVIYXNoVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHMoYnVuZGxlLmJ1bmRsZVtpXS5idW5kbGUpO1xuICAgICAgICAgICAgdmFyIGhtYWMgPSBuZXcgSW50OEFycmF5KDI0Myk7XG4gICAgICAgICAgICBjdXJsLmluaXRpYWxpemUoKTtcbiAgICAgICAgICAgIGN1cmwuYWJzb3JiKGtleSk7XG4gICAgICAgICAgICBjdXJsLmFic29yYihidW5kbGVIYXNoVHJpdHMpO1xuICAgICAgICAgICAgY3VybC5zcXVlZXplKGhtYWMpO1xuICAgICAgICAgICAgdmFyIGhtYWNUcnl0ZXMgPSBDb252ZXJ0ZXIudHJ5dGVzKGhtYWMpO1xuICAgICAgICAgICAgYnVuZGxlLmJ1bmRsZVtpXS5zaWduYXR1cmVNZXNzYWdlRnJhZ21lbnQgPSBobWFjVHJ5dGVzICsgYnVuZGxlLmJ1bmRsZVtpXS5zaWduYXR1cmVNZXNzYWdlRnJhZ21lbnQuc3Vic3RyaW5nKDgxLCAyMTg3KTtcbiAgICAgICAgfVxuICAgIH1cbn1cblxubW9kdWxlLmV4cG9ydHMgPSBobWFjO1xuIiwidmFyIENyeXB0b0pTID0gcmVxdWlyZShcImNyeXB0by1qc1wiKTtcbnZhciBDb252ZXJ0ZXIgPSByZXF1aXJlKFwiLi4vY29udmVydGVyL2NvbnZlcnRlclwiKTtcbnZhciBDdXJsID0gcmVxdWlyZShcIi4uL2N1cmwvY3VybFwiKTtcbnZhciBXQ29udmVydGVyID0gcmVxdWlyZShcIi4uL2NvbnZlcnRlci93b3Jkc1wiKTtcblxudmFyIEJJVF9IQVNIX0xFTkdUSCA9IDM4NDtcblxuZnVuY3Rpb24gS2VybCgpIHtcblxuXG4gICAgdGhpcy5rID0gQ3J5cHRvSlMuYWxnby5TSEEzLmNyZWF0ZSgpO1xuICAgIHRoaXMuay5pbml0KHtcbiAgICAgICAgb3V0cHV0TGVuZ3RoOiBCSVRfSEFTSF9MRU5HVEhcbiAgICB9KTtcbn1cblxuS2VybC5CSVRfSEFTSF9MRU5HVEggPSBCSVRfSEFTSF9MRU5HVEg7XG5LZXJsLkhBU0hfTEVOR1RIID0gQ3VybC5IQVNIX0xFTkdUSDtcblxuS2VybC5wcm90b3R5cGUuaW5pdGlhbGl6ZSA9IGZ1bmN0aW9uKHN0YXRlKSB7fVxuXG5LZXJsLnByb3RvdHlwZS5yZXNldCA9IGZ1bmN0aW9uKCkge1xuXG4gICAgdGhpcy5rLnJlc2V0KCk7XG5cbn1cblxuS2VybC5wcm90b3R5cGUuYWJzb3JiID0gZnVuY3Rpb24odHJpdHMsIG9mZnNldCwgbGVuZ3RoKSB7XG5cblxuICAgIGlmIChsZW5ndGggJiYgKChsZW5ndGggJSAyNDMpICE9PSAwKSkge1xuXG4gICAgICAgIHRocm93IG5ldyBFcnJvcignSWxsZWdhbCBsZW5ndGggcHJvdmlkZWQnKTtcblxuICAgIH1cblxuICAgIGRvIHtcbiAgICAgICAgdmFyIGxpbWl0ID0gKGxlbmd0aCA8IEN1cmwuSEFTSF9MRU5HVEggPyBsZW5ndGggOiBDdXJsLkhBU0hfTEVOR1RIKTtcblxuICAgICAgICB2YXIgdHJpdF9zdGF0ZSA9IHRyaXRzLnNsaWNlKG9mZnNldCwgb2Zmc2V0ICsgbGltaXQpO1xuICAgICAgICBvZmZzZXQgKz0gbGltaXQ7XG5cbiAgICAgICAgLy8gY29udmVydCB0cml0IHN0YXRlIHRvIHdvcmRzXG4gICAgICAgIHZhciB3b3Jkc1RvQWJzb3JiID0gV0NvbnZlcnRlci50cml0c190b193b3Jkcyh0cml0X3N0YXRlKTtcblxuICAgICAgICAvLyBhYnNvcmIgdGhlIHRyaXQgc3RhdCBhcyB3b3JkYXJyYXlcbiAgICAgICAgdGhpcy5rLnVwZGF0ZShcbiAgICAgICAgICAgIENyeXB0b0pTLmxpYi5Xb3JkQXJyYXkuY3JlYXRlKHdvcmRzVG9BYnNvcmIpKTtcblxuICAgIH0gd2hpbGUgKChsZW5ndGggLT0gQ3VybC5IQVNIX0xFTkdUSCkgPiAwKTtcblxufVxuXG5cblxuS2VybC5wcm90b3R5cGUuc3F1ZWV6ZSA9IGZ1bmN0aW9uKHRyaXRzLCBvZmZzZXQsIGxlbmd0aCkge1xuXG4gICAgaWYgKGxlbmd0aCAmJiAoKGxlbmd0aCAlIDI0MykgIT09IDApKSB7XG5cbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdJbGxlZ2FsIGxlbmd0aCBwcm92aWRlZCcpO1xuXG4gICAgfVxuICAgIGRvIHtcblxuICAgICAgICAvLyBnZXQgdGhlIGhhc2ggZGlnZXN0XG4gICAgICAgIHZhciBrQ29weSA9IHRoaXMuay5jbG9uZSgpO1xuICAgICAgICB2YXIgZmluYWwgPSBrQ29weS5maW5hbGl6ZSgpO1xuXG4gICAgICAgIC8vIENvbnZlcnQgd29yZHMgdG8gdHJpdHMgYW5kIHRoZW4gbWFwIGl0IGludG8gdGhlIGludGVybmFsIHN0YXRlXG4gICAgICAgIHZhciB0cml0X3N0YXRlID0gV0NvbnZlcnRlci53b3Jkc190b190cml0cyhmaW5hbC53b3Jkcyk7XG5cbiAgICAgICAgdmFyIGkgPSAwO1xuICAgICAgICB2YXIgbGltaXQgPSAobGVuZ3RoIDwgQ3VybC5IQVNIX0xFTkdUSCA/IGxlbmd0aCA6IEN1cmwuSEFTSF9MRU5HVEgpO1xuXG4gICAgICAgIHdoaWxlIChpIDwgbGltaXQpIHtcbiAgICAgICAgICAgIHRyaXRzW29mZnNldCsrXSA9IHRyaXRfc3RhdGVbaSsrXTtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMucmVzZXQoKTtcblxuICAgICAgICBmb3IgKGkgPSAwOyBpIDwgZmluYWwud29yZHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGZpbmFsLndvcmRzW2ldID0gZmluYWwud29yZHNbaV0gXiAweEZGRkZGRkZGO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy5rLnVwZGF0ZShmaW5hbCk7XG5cbiAgICB9IHdoaWxlICgobGVuZ3RoIC09IEN1cmwuSEFTSF9MRU5HVEgpID4gMCk7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gS2VybDtcbiIsInZhciBDdXJsID0gcmVxdWlyZShcIi4uL2N1cmwvY3VybFwiKTtcbnZhciBDb252ZXJ0ZXIgPSByZXF1aXJlKFwiLi4vY29udmVydGVyL2NvbnZlcnRlclwiKTtcbnZhciBCdW5kbGUgPSByZXF1aXJlKFwiLi4vYnVuZGxlL2J1bmRsZVwiKTtcbnZhciBhZGQgPSByZXF1aXJlKFwiLi4vaGVscGVycy9hZGRlclwiKTtcblxuLyoqXG4qICAgICAgICAgICBTaWduaW5nIHJlbGF0ZWQgZnVuY3Rpb25zXG4qXG4qKi9cbnZhciBrZXkgPSBmdW5jdGlvbihzZWVkLCBpbmRleCwgbGVuZ3RoKSB7XG5cbiAgICB3aGlsZSAoKHNlZWQubGVuZ3RoICUgMjQzKSAhPT0gMCkge1xuICAgICAgc2VlZC5wdXNoKDApO1xuICAgIH1cblxuICAgIHZhciBpbmRleFRyaXRzID0gQ29udmVydGVyLmZyb21WYWx1ZSggaW5kZXggKTtcbiAgICB2YXIgc3Vic2VlZCA9IGFkZCggc2VlZC5zbGljZSggKSwgaW5kZXhUcml0cyApO1xuXG4gICAgdmFyIGN1cmwgPSBuZXcgQ3VybCggKTtcblxuICAgIGN1cmwuaW5pdGlhbGl6ZSggKTtcbiAgICBjdXJsLmFic29yYihzdWJzZWVkLCAwLCBzdWJzZWVkLmxlbmd0aCk7XG4gICAgY3VybC5zcXVlZXplKHN1YnNlZWQsIDAsIHN1YnNlZWQubGVuZ3RoKTtcblxuICAgIGN1cmwuaW5pdGlhbGl6ZSggKTtcbiAgICBjdXJsLmFic29yYihzdWJzZWVkLCAwLCBzdWJzZWVkLmxlbmd0aCk7XG5cbiAgICB2YXIga2V5ID0gW10sIG9mZnNldCA9IDAsIGJ1ZmZlciA9IFtdO1xuXG4gICAgd2hpbGUgKGxlbmd0aC0tID4gMCkge1xuXG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMjc7IGkrKykge1xuXG4gICAgICAgICAgICBjdXJsLnNxdWVlemUoYnVmZmVyLCAwLCBzdWJzZWVkLmxlbmd0aCk7XG4gICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI0MzsgaisrKSB7XG5cbiAgICAgICAgICAgICAgICBrZXlbb2Zmc2V0KytdID0gYnVmZmVyW2pdO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBrZXk7XG59XG5cbi8qKlxuKlxuKlxuKiovXG52YXIgZGlnZXN0cyA9IGZ1bmN0aW9uKGtleSkge1xuXG4gICAgdmFyIGRpZ2VzdHMgPSBbXSwgYnVmZmVyID0gW107XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IE1hdGguZmxvb3Ioa2V5Lmxlbmd0aCAvIDY1NjEpOyBpKyspIHtcblxuICAgICAgICB2YXIga2V5RnJhZ21lbnQgPSBrZXkuc2xpY2UoaSAqIDY1NjEsIChpICsgMSkgKiA2NTYxKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI3OyBqKyspIHtcblxuICAgICAgICAgICAgYnVmZmVyID0ga2V5RnJhZ21lbnQuc2xpY2UoaiAqIDI0MywgKGogKyAxKSAqIDI0Myk7XG5cbiAgICAgICAgICAgIGZvciAodmFyIGsgPSAwOyBrIDwgMjY7IGsrKykge1xuXG4gICAgICAgICAgICAgICAgdmFyIGtDdXJsID0gbmV3IEN1cmwoKTtcbiAgICAgICAgICAgICAgICBrQ3VybC5pbml0aWFsaXplKCk7XG4gICAgICAgICAgICAgICAga0N1cmwuYWJzb3JiKGJ1ZmZlciwgMCwgYnVmZmVyLmxlbmd0aCk7XG4gICAgICAgICAgICAgICAga0N1cmwuc3F1ZWV6ZShidWZmZXIsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmb3IgKHZhciBrID0gMDsgayA8IDI0MzsgaysrKSB7XG5cbiAgICAgICAgICAgICAgICBrZXlGcmFnbWVudFtqICogMjQzICsga10gPSBidWZmZXJba107XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICB2YXIgY3VybCA9IG5ldyBDdXJsKClcblxuICAgICAgICBjdXJsLmluaXRpYWxpemUoKTtcbiAgICAgICAgY3VybC5hYnNvcmIoa2V5RnJhZ21lbnQsIDAsIGtleUZyYWdtZW50Lmxlbmd0aCk7XG4gICAgICAgIGN1cmwuc3F1ZWV6ZShidWZmZXIsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuXG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMjQzOyBqKyspIHtcblxuICAgICAgICAgICAgZGlnZXN0c1tpICogMjQzICsgal0gPSBidWZmZXJbal07XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIGRpZ2VzdHM7XG59XG5cbi8qKlxuKlxuKlxuKiovXG52YXIgYWRkcmVzcyA9IGZ1bmN0aW9uKGRpZ2VzdHMpIHtcblxuICAgIHZhciBhZGRyZXNzVHJpdHMgPSBbXTtcblxuICAgIHZhciBjdXJsID0gbmV3IEN1cmwoKTtcblxuICAgIGN1cmwuaW5pdGlhbGl6ZSgpO1xuICAgIGN1cmwuYWJzb3JiKGRpZ2VzdHMsIDAsIGRpZ2VzdHMubGVuZ3RoKTtcbiAgICBjdXJsLnNxdWVlemUoYWRkcmVzc1RyaXRzLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcblxuICAgIHJldHVybiBhZGRyZXNzVHJpdHM7XG59XG5cbi8qKlxuKlxuKlxuKiovXG52YXIgZGlnZXN0ID0gZnVuY3Rpb24obm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50LCBzaWduYXR1cmVGcmFnbWVudCkge1xuXG4gICAgdmFyIGJ1ZmZlciA9IFtdXG5cbiAgICB2YXIgY3VybCA9IG5ldyBDdXJsKCk7XG5cbiAgICBjdXJsLmluaXRpYWxpemUoKTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpPCAyNzsgaSsrKSB7XG4gICAgICAgIGJ1ZmZlciA9IHNpZ25hdHVyZUZyYWdtZW50LnNsaWNlKGkgKiAyNDMsIChpICsgMSkgKiAyNDMpO1xuXG4gICAgICAgIGZvciAodmFyIGogPSBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRbaV0gKyAxMzsgai0tID4gMDsgKSB7XG5cbiAgICAgICAgICAgIHZhciBqQ3VybCA9IG5ldyBDdXJsKCk7XG5cbiAgICAgICAgICAgIGpDdXJsLmluaXRpYWxpemUoKTtcbiAgICAgICAgICAgIGpDdXJsLmFic29yYihidWZmZXIsIDAsIGJ1ZmZlci5sZW5ndGgpO1xuICAgICAgICAgICAgakN1cmwuc3F1ZWV6ZShidWZmZXIsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuICAgICAgICB9XG5cbiAgICAgICAgY3VybC5hYnNvcmIoYnVmZmVyLCAwLCBidWZmZXIubGVuZ3RoKTtcbiAgICB9XG5cbiAgICBjdXJsLnNxdWVlemUoYnVmZmVyLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcbiAgICByZXR1cm4gYnVmZmVyO1xufVxuXG4vKipcbipcbipcbioqL1xudmFyIHNpZ25hdHVyZUZyYWdtZW50ID0gZnVuY3Rpb24obm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50LCBrZXlGcmFnbWVudCkge1xuXG4gICAgdmFyIHNpZ25hdHVyZUZyYWdtZW50ID0ga2V5RnJhZ21lbnQuc2xpY2UoKSwgaGFzaCA9IFtdO1xuXG4gICAgdmFyIGN1cmwgPSBuZXcgQ3VybCgpO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNzsgaSsrKSB7XG5cbiAgICAgICAgaGFzaCA9IHNpZ25hdHVyZUZyYWdtZW50LnNsaWNlKGkgKiAyNDMsIChpICsgMSkgKiAyNDMpO1xuXG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMTMgLSBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRbaV07IGorKykge1xuXG4gICAgICAgICAgICBjdXJsLmluaXRpYWxpemUoKTtcbiAgICAgICAgICAgIGN1cmwuYWJzb3JiKGhhc2gsIDAsIGhhc2gubGVuZ3RoKTtcbiAgICAgICAgICAgIGN1cmwuc3F1ZWV6ZShoYXNoLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMjQzOyBqKyspIHtcblxuICAgICAgICAgICAgc2lnbmF0dXJlRnJhZ21lbnRbaSAqIDI0MyArIGpdID0gaGFzaFtqXTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiBzaWduYXR1cmVGcmFnbWVudDtcbn1cblxuLyoqXG4qXG4qXG4qKi9cbnZhciB2YWxpZGF0ZVNpZ25hdHVyZXMgPSBmdW5jdGlvbihleHBlY3RlZEFkZHJlc3MsIHNpZ25hdHVyZUZyYWdtZW50cywgYnVuZGxlSGFzaCkge1xuXG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuICAgIHZhciBidW5kbGUgPSBuZXcgQnVuZGxlKCk7XG5cbiAgICB2YXIgbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50cyA9IFtdO1xuICAgIHZhciBub3JtYWxpemVkQnVuZGxlSGFzaCA9IGJ1bmRsZS5ub3JtYWxpemVkQnVuZGxlKGJ1bmRsZUhhc2gpO1xuXG4gICAgLy8gU3BsaXQgaGFzaCBpbnRvIDMgZnJhZ21lbnRzXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCAzOyBpKyspIHtcbiAgICAgICAgbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50c1tpXSA9IG5vcm1hbGl6ZWRCdW5kbGVIYXNoLnNsaWNlKGkgKiAyNywgKGkgKyAxKSAqIDI3KTtcbiAgICB9XG5cbiAgICAvLyBHZXQgZGlnZXN0c1xuICAgIHZhciBkaWdlc3RzID0gW107XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHNpZ25hdHVyZUZyYWdtZW50cy5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIHZhciBkaWdlc3RCdWZmZXIgPSBkaWdlc3Qobm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50c1tpICUgM10sIENvbnZlcnRlci50cml0cyhzaWduYXR1cmVGcmFnbWVudHNbaV0pKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI0MzsgaisrKSB7XG5cbiAgICAgICAgICAgIGRpZ2VzdHNbaSAqIDI0MyArIGpdID0gZGlnZXN0QnVmZmVyW2pdXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICB2YXIgYWRkcmVzcyA9IENvbnZlcnRlci50cnl0ZXMoc2VsZi5hZGRyZXNzKGRpZ2VzdHMpKTtcblxuICAgIHJldHVybiAoZXhwZWN0ZWRBZGRyZXNzID09PSBhZGRyZXNzKTtcbn1cblxuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgICBrZXkgICAgICAgICAgICAgICAgIDoga2V5LFxuICAgIGRpZ2VzdHMgICAgICAgICAgICAgOiBkaWdlc3RzLFxuICAgIGFkZHJlc3MgICAgICAgICAgICAgOiBhZGRyZXNzLFxuICAgIGRpZ2VzdCAgICAgICAgICAgICAgOiBkaWdlc3QsXG4gICAgc2lnbmF0dXJlRnJhZ21lbnQgICA6IHNpZ25hdHVyZUZyYWdtZW50LFxuICAgIHZhbGlkYXRlU2lnbmF0dXJlcyAgOiB2YWxpZGF0ZVNpZ25hdHVyZXNcbn1cbiIsInZhciBDdXJsID0gcmVxdWlyZShcIi4uL2N1cmwvY3VybFwiKTtcbnZhciBLZXJsID0gcmVxdWlyZShcIi4uL2tlcmwva2VybFwiKTtcbnZhciBDb252ZXJ0ZXIgPSByZXF1aXJlKFwiLi4vY29udmVydGVyL2NvbnZlcnRlclwiKTtcbnZhciBCdW5kbGUgPSByZXF1aXJlKFwiLi4vYnVuZGxlL2J1bmRsZVwiKTtcbnZhciBhZGQgPSByZXF1aXJlKFwiLi4vaGVscGVycy9hZGRlclwiKTtcbnZhciBvbGRTaWduaW5nID0gcmVxdWlyZShcIi4vb2xkU2lnbmluZ1wiKTtcbnZhciBlcnJvcnMgPSByZXF1aXJlKFwiLi4vLi4vZXJyb3JzL2lucHV0RXJyb3JzXCIpO1xuXG4vKipcbiogICAgICAgICAgIFNpZ25pbmcgcmVsYXRlZCBmdW5jdGlvbnNcbipcbioqL1xudmFyIGtleSA9IGZ1bmN0aW9uKHNlZWQsIGluZGV4LCBsZW5ndGgpIHtcblxuICAgIHdoaWxlICgoc2VlZC5sZW5ndGggJSAyNDMpICE9PSAwKSB7XG4gICAgICBzZWVkLnB1c2goMCk7XG4gICAgfVxuXG4gICAgdmFyIGluZGV4VHJpdHMgPSBDb252ZXJ0ZXIuZnJvbVZhbHVlKCBpbmRleCApO1xuICAgIHZhciBzdWJzZWVkID0gYWRkKCBzZWVkLnNsaWNlKCApLCBpbmRleFRyaXRzICk7XG5cbiAgICB2YXIga2VybCA9IG5ldyBLZXJsKCApO1xuXG4gICAga2VybC5pbml0aWFsaXplKCApO1xuICAgIGtlcmwuYWJzb3JiKHN1YnNlZWQsIDAsIHN1YnNlZWQubGVuZ3RoKTtcbiAgICBrZXJsLnNxdWVlemUoc3Vic2VlZCwgMCwgc3Vic2VlZC5sZW5ndGgpO1xuXG4gICAga2VybC5yZXNldCggKTtcbiAgICBrZXJsLmFic29yYihzdWJzZWVkLCAwLCBzdWJzZWVkLmxlbmd0aCk7XG5cbiAgICB2YXIga2V5ID0gW10sIG9mZnNldCA9IDAsIGJ1ZmZlciA9IFtdO1xuXG4gICAgd2hpbGUgKGxlbmd0aC0tID4gMCkge1xuXG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMjc7IGkrKykge1xuXG4gICAgICAgICAgICBrZXJsLnNxdWVlemUoYnVmZmVyLCAwLCBzdWJzZWVkLmxlbmd0aCk7XG4gICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI0MzsgaisrKSB7XG5cbiAgICAgICAgICAgICAgICBrZXlbb2Zmc2V0KytdID0gYnVmZmVyW2pdO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBrZXk7XG59XG5cbi8qKlxuKlxuKlxuKiovXG52YXIgZGlnZXN0cyA9IGZ1bmN0aW9uKGtleSkge1xuXG4gICAgdmFyIGRpZ2VzdHMgPSBbXSwgYnVmZmVyID0gW107XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IE1hdGguZmxvb3Ioa2V5Lmxlbmd0aCAvIDY1NjEpOyBpKyspIHtcblxuICAgICAgICB2YXIga2V5RnJhZ21lbnQgPSBrZXkuc2xpY2UoaSAqIDY1NjEsIChpICsgMSkgKiA2NTYxKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI3OyBqKyspIHtcblxuICAgICAgICAgICAgYnVmZmVyID0ga2V5RnJhZ21lbnQuc2xpY2UoaiAqIDI0MywgKGogKyAxKSAqIDI0Myk7XG5cbiAgICAgICAgICAgIGZvciAodmFyIGsgPSAwOyBrIDwgMjY7IGsrKykge1xuXG4gICAgICAgICAgICAgICAgdmFyIGtLZXJsID0gbmV3IEtlcmwoKTtcbiAgICAgICAgICAgICAgICBrS2VybC5pbml0aWFsaXplKCk7XG4gICAgICAgICAgICAgICAga0tlcmwuYWJzb3JiKGJ1ZmZlciwgMCwgYnVmZmVyLmxlbmd0aCk7XG4gICAgICAgICAgICAgICAga0tlcmwuc3F1ZWV6ZShidWZmZXIsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBmb3IgKHZhciBrID0gMDsgayA8IDI0MzsgaysrKSB7XG5cbiAgICAgICAgICAgICAgICBrZXlGcmFnbWVudFtqICogMjQzICsga10gPSBidWZmZXJba107XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICB2YXIga2VybCA9IG5ldyBLZXJsKClcblxuICAgICAgICBrZXJsLmluaXRpYWxpemUoKTtcbiAgICAgICAga2VybC5hYnNvcmIoa2V5RnJhZ21lbnQsIDAsIGtleUZyYWdtZW50Lmxlbmd0aCk7XG4gICAgICAgIGtlcmwuc3F1ZWV6ZShidWZmZXIsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuXG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMjQzOyBqKyspIHtcblxuICAgICAgICAgICAgZGlnZXN0c1tpICogMjQzICsgal0gPSBidWZmZXJbal07XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIGRpZ2VzdHM7XG59XG5cbi8qKlxuKlxuKlxuKiovXG52YXIgYWRkcmVzcyA9IGZ1bmN0aW9uKGRpZ2VzdHMpIHtcblxuICAgIHZhciBhZGRyZXNzVHJpdHMgPSBbXTtcblxuICAgIHZhciBrZXJsID0gbmV3IEtlcmwoKTtcblxuICAgIGtlcmwuaW5pdGlhbGl6ZSgpO1xuICAgIGtlcmwuYWJzb3JiKGRpZ2VzdHMsIDAsIGRpZ2VzdHMubGVuZ3RoKTtcbiAgICBrZXJsLnNxdWVlemUoYWRkcmVzc1RyaXRzLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcblxuICAgIHJldHVybiBhZGRyZXNzVHJpdHM7XG59XG5cbi8qKlxuKlxuKlxuKiovXG52YXIgZGlnZXN0ID0gZnVuY3Rpb24obm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50LCBzaWduYXR1cmVGcmFnbWVudCkge1xuXG4gICAgdmFyIGJ1ZmZlciA9IFtdXG5cbiAgICB2YXIga2VybCA9IG5ldyBLZXJsKCk7XG5cbiAgICBrZXJsLmluaXRpYWxpemUoKTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpPCAyNzsgaSsrKSB7XG4gICAgICAgIGJ1ZmZlciA9IHNpZ25hdHVyZUZyYWdtZW50LnNsaWNlKGkgKiAyNDMsIChpICsgMSkgKiAyNDMpO1xuXG4gICAgICAgIGZvciAodmFyIGogPSBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRbaV0gKyAxMzsgai0tID4gMDsgKSB7XG5cbiAgICAgICAgICAgIHZhciBqS2VybCA9IG5ldyBLZXJsKCk7XG5cbiAgICAgICAgICAgIGpLZXJsLmluaXRpYWxpemUoKTtcbiAgICAgICAgICAgIGpLZXJsLmFic29yYihidWZmZXIsIDAsIGJ1ZmZlci5sZW5ndGgpO1xuICAgICAgICAgICAgaktlcmwuc3F1ZWV6ZShidWZmZXIsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuICAgICAgICB9XG5cbiAgICAgICAga2VybC5hYnNvcmIoYnVmZmVyLCAwLCBidWZmZXIubGVuZ3RoKTtcbiAgICB9XG5cbiAgICBrZXJsLnNxdWVlemUoYnVmZmVyLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcbiAgICByZXR1cm4gYnVmZmVyO1xufVxuXG4vKipcbipcbipcbioqL1xudmFyIHNpZ25hdHVyZUZyYWdtZW50ID0gZnVuY3Rpb24obm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50LCBrZXlGcmFnbWVudCkge1xuXG4gICAgdmFyIHNpZ25hdHVyZUZyYWdtZW50ID0ga2V5RnJhZ21lbnQuc2xpY2UoKSwgaGFzaCA9IFtdO1xuXG4gICAgdmFyIGtlcmwgPSBuZXcgS2VybCgpO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNzsgaSsrKSB7XG5cbiAgICAgICAgaGFzaCA9IHNpZ25hdHVyZUZyYWdtZW50LnNsaWNlKGkgKiAyNDMsIChpICsgMSkgKiAyNDMpO1xuXG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMTMgLSBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRbaV07IGorKykge1xuXG4gICAgICAgICAgICBrZXJsLmluaXRpYWxpemUoKTtcbiAgICAgICAgICAgIGtlcmwucmVzZXQoKTtcbiAgICAgICAgICAgIGtlcmwuYWJzb3JiKGhhc2gsIDAsIGhhc2gubGVuZ3RoKTtcbiAgICAgICAgICAgIGtlcmwuc3F1ZWV6ZShoYXNoLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMjQzOyBqKyspIHtcblxuICAgICAgICAgICAgc2lnbmF0dXJlRnJhZ21lbnRbaSAqIDI0MyArIGpdID0gaGFzaFtqXTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiBzaWduYXR1cmVGcmFnbWVudDtcbn1cblxuLyoqXG4qXG4qXG4qKi9cbnZhciB2YWxpZGF0ZVNpZ25hdHVyZXMgPSBmdW5jdGlvbihleHBlY3RlZEFkZHJlc3MsIHNpZ25hdHVyZUZyYWdtZW50cywgYnVuZGxlSGFzaCkge1xuICAgIGlmICghYnVuZGxlSGFzaCkge1xuICAgICAgICB0aHJvdyBlcnJvcnMuaW52YWxpZEJ1bmRsZUhhc2goKTtcbiAgICB9XG5cbiAgICB2YXIgc2VsZiA9IHRoaXM7XG4gICAgdmFyIGJ1bmRsZSA9IG5ldyBCdW5kbGUoKTtcblxuICAgIHZhciBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRzID0gW107XG4gICAgdmFyIG5vcm1hbGl6ZWRCdW5kbGVIYXNoID0gYnVuZGxlLm5vcm1hbGl6ZWRCdW5kbGUoYnVuZGxlSGFzaCk7XG5cbiAgICAvLyBTcGxpdCBoYXNoIGludG8gMyBmcmFnbWVudHNcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IDM7IGkrKykge1xuICAgICAgICBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRzW2ldID0gbm9ybWFsaXplZEJ1bmRsZUhhc2guc2xpY2UoaSAqIDI3LCAoaSArIDEpICogMjcpO1xuICAgIH1cblxuICAgIC8vIEdldCBkaWdlc3RzXG4gICAgdmFyIGRpZ2VzdHMgPSBbXTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2lnbmF0dXJlRnJhZ21lbnRzLmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgdmFyIGRpZ2VzdEJ1ZmZlciA9IGRpZ2VzdChub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRzW2kgJSAzXSwgQ29udmVydGVyLnRyaXRzKHNpZ25hdHVyZUZyYWdtZW50c1tpXSkpO1xuXG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMjQzOyBqKyspIHtcblxuICAgICAgICAgICAgZGlnZXN0c1tpICogMjQzICsgal0gPSBkaWdlc3RCdWZmZXJbal1cbiAgICAgICAgfVxuICAgIH1cblxuICAgIHZhciBhZGRyZXNzID0gQ29udmVydGVyLnRyeXRlcyhzZWxmLmFkZHJlc3MoZGlnZXN0cykpO1xuXG4gICAgcmV0dXJuIChleHBlY3RlZEFkZHJlc3MgPT09IGFkZHJlc3MpO1xufVxuXG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICAgIGtleSAgICAgICAgICAgICAgICAgOiBrZXksXG4gICAgZGlnZXN0cyAgICAgICAgICAgICA6IGRpZ2VzdHMsXG4gICAgYWRkcmVzcyAgICAgICAgICAgICA6IGFkZHJlc3MsXG4gICAgZGlnZXN0ICAgICAgICAgICAgICA6IGRpZ2VzdCxcbiAgICBzaWduYXR1cmVGcmFnbWVudCAgIDogc2lnbmF0dXJlRnJhZ21lbnQsXG4gICAgdmFsaWRhdGVTaWduYXR1cmVzICA6IHZhbGlkYXRlU2lnbmF0dXJlc1xufVxuIiwiXG5tb2R1bGUuZXhwb3J0cyA9IHtcblxuICAgIGludmFsaWRUcnl0ZXM6IGZ1bmN0aW9uKCkge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiSW52YWxpZCBUcnl0ZXMgcHJvdmlkZWRcIik7XG4gICAgfSxcbiAgICBpbnZhbGlkU2VlZDogZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBuZXcgRXJyb3IoXCJJbnZhbGlkIFNlZWQgcHJvdmlkZWRcIik7XG4gICAgfSxcbiAgICBpbnZhbGlkSW5kZXg6IGZ1bmN0aW9uKCkge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiSW52YWxpZCBJbmRleCBvcHRpb24gcHJvdmlkZWRcIik7XG4gICAgfSwgXG4gICAgaW52YWxpZFNlY3VyaXR5OiBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBFcnJvcihcIkludmFsaWQgU2VjdXJpdHkgb3B0aW9uIHByb3ZpZGVkXCIpO1xuICAgIH0sXG4gICAgaW52YWxpZENoZWNrc3VtOiBmdW5jdGlvbihhZGRyZXNzKSB7XG4gICAgICAgIHJldHVybiBuZXcgRXJyb3IoXCJJbnZhbGlkIENoZWNrc3VtIHN1cHBsaWVkIGZvciBhZGRyZXNzOiBcIiArIGFkZHJlc3MpXG4gICAgfSxcbiAgICBpbnZhbGlkQXR0YWNoZWRUcnl0ZXM6IGZ1bmN0aW9uKCkge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiSW52YWxpZCBhdHRhY2hlZCBUcnl0ZXMgcHJvdmlkZWRcIik7XG4gICAgfSxcbiAgICBpbnZhbGlkVHJhbnNmZXJzOiBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBFcnJvcihcIkludmFsaWQgdHJhbnNmZXJzIG9iamVjdFwiKTtcbiAgICB9LFxuICAgIGludmFsaWRLZXk6IGZ1bmN0aW9uKCkge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiWW91IGhhdmUgcHJvdmlkZWQgYW4gaW52YWxpZCBrZXkgdmFsdWVcIik7XG4gICAgfSxcbiAgICBpbnZhbGlkVHJ1bmtPckJyYW5jaDogZnVuY3Rpb24oaGFzaCkge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiWW91IGhhdmUgcHJvdmlkZWQgYW4gaW52YWxpZCBoYXNoIGFzIGEgdHJ1bmsvYnJhbmNoOiBcIiArIGhhc2gpO1xuICAgIH0sXG4gICAgaW52YWxpZFVyaTogZnVuY3Rpb24odXJpKSB7XG4gICAgICAgIHJldHVybiBuZXcgRXJyb3IoXCJZb3UgaGF2ZSBwcm92aWRlZCBhbiBpbnZhbGlkIFVSSSBmb3IgeW91ciBOZWlnaGJvcjogXCIgKyB1cmkpXG4gICAgfSxcbiAgICBub3RJbnQ6IGZ1bmN0aW9uKCkge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiT25lIG9mIHlvdXIgaW5wdXRzIGlzIG5vdCBhbiBpbnRlZ2VyXCIpO1xuICAgIH0sXG4gICAgaW52YWxpZElucHV0czogZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBuZXcgRXJyb3IoXCJJbnZhbGlkIGlucHV0cyBwcm92aWRlZFwiKTtcbiAgICB9XG59XG4iLCJtb2R1bGUuZXhwb3J0cyA9IHtcbiAgY3VybDogcmVxdWlyZSgnLi9jcnlwdG8vY3VybC9jdXJsJyksXG4gIGtlcmw6IHJlcXVpcmUoJy4vY3J5cHRvL2tlcmwva2VybCcpLFxuICBidW5kbGU6IHJlcXVpcmUoJy4vY3J5cHRvL2J1bmRsZS9idW5kbGUnKSxcbiAgY29udmVydGVyOiByZXF1aXJlKCcuL2NyeXB0by9jb252ZXJ0ZXIvY29udmVydGVyJyksXG4gIHNpZ25pbmc6IHJlcXVpcmUoJy4vY3J5cHRvL3NpZ25pbmcvc2lnbmluZycpLFxuICBvbGRTaWduaW5nOiByZXF1aXJlKCcuL2NyeXB0by9zaWduaW5nL29sZFNpZ25pbmcnKSxcbiAgaG1hYzogcmVxdWlyZSgnLi9jcnlwdG8vaG1hYy9obWFjJyksXG4gIG11bHRpc2lnOiByZXF1aXJlKCcuL211bHRpc2lnL211bHRpc2lnJyksXG4gIHV0aWxzOiByZXF1aXJlKFwiLi91dGlscy91dGlsc1wiKSxcbiAgdmFsaWQ6IHJlcXVpcmUoXCIuL2Vycm9ycy9pbnB1dEVycm9yc1wiKSxcbiAgYWRkOiByZXF1aXJlKFwiLi9jcnlwdG8vaGVscGVycy9hZGRlclwiKVxufVxuIiwidmFyIENvbnZlcnRlciAgICAgID0gIHJlcXVpcmUoJy4uL2NyeXB0by9jb252ZXJ0ZXIvY29udmVydGVyJyk7XG52YXIgQ3VybCAgICAgICAgICAgPSAgcmVxdWlyZSgnLi4vY3J5cHRvL2N1cmwvY3VybCcpO1xudmFyIEtlcmwgICAgICAgICAgID0gIHJlcXVpcmUoJy4uL2NyeXB0by9rZXJsL2tlcmwnKTtcbnZhciBTaWduaW5nICAgICAgICA9ICByZXF1aXJlKCcuLi9jcnlwdG8vc2lnbmluZy9zaWduaW5nJyk7XG52YXIgVXRpbHMgICAgICAgICAgPSAgcmVxdWlyZSgnLi4vdXRpbHMvdXRpbHMnKTtcbnZhciBpbnB1dFZhbGlkYXRvciA9ICByZXF1aXJlKCcuLi91dGlscy9pbnB1dFZhbGlkYXRvcicpO1xuXG5cbi8qKlxuKiAgIEluaXRpYWxpemVzIGEgbmV3IG11bHRpc2lnIGFkZHJlc3NcbipcbiogICBAbWV0aG9kIGFkZERpZ2VzdFxuKiAgIEBwYXJhbSB7c3RyaW5nfGFycmF5fSBkaWdlc3QgZGlnZXN0IHRyeXRlc1xuKiAgIEByZXR1cm4ge29iamVjdH0gYWRkcmVzcyBpbnN0YW5jZVxuKlxuKiovXG5mdW5jdGlvbiBBZGRyZXNzKGRpZ2VzdHMpIHtcblxuICBpZiAoISh0aGlzIGluc3RhbmNlb2YgQWRkcmVzcykpIHtcbiAgICByZXR1cm4gbmV3IEFkZHJlc3MoZGlnZXN0cyk7XG4gIH1cblxuICAvLyBJbml0aWFsaXplIGtlcmwgaW5zdGFuY2VcbiAgdGhpcy5fa2VybCA9IG5ldyBLZXJsKCk7XG4gIHRoaXMuX2tlcmwuaW5pdGlhbGl6ZSgpO1xuXG5cbiAgLy8gQWRkIGRpZ2VzdHMgaWYgYW55XG4gIGlmIChkaWdlc3RzKSB7XG5cbiAgICB0aGlzLmFic29yYihkaWdlc3RzKTtcbiAgfVxufVxuXG4vKipcbiogICBBYnNvcmJzIGtleSBkaWdlc3RzXG4qXG4qICAgQG1ldGhvZCBhYnNvcmJcbiogICBAcGFyYW0ge3N0cmluZ3xhcnJheX0gZGlnZXN0IGRpZ2VzdCB0cnl0ZXNcbiogICBAcmV0dXJuIHtvYmplY3R9IGFkZHJlc3MgaW5zdGFuY2VcbipcbioqL1xuQWRkcmVzcy5wcm90b3R5cGUuYWJzb3JiID0gZnVuY3Rpb24gKGRpZ2VzdCkge1xuXG4gIC8vIENvbnN0cnVjdCBhcnJheVxuICB2YXIgZGlnZXN0cyA9IEFycmF5LmlzQXJyYXkoZGlnZXN0KSA/IGRpZ2VzdCA6IFtkaWdlc3RdO1xuXG4gIC8vIEFkZCBkaWdlc3RzXG4gIGZvciAodmFyIGkgPSAwOyBpIDwgZGlnZXN0cy5sZW5ndGg7IGkrKykge1xuXG4gICAgLy8gR2V0IHRyaXRzIG9mIGRpZ2VzdFxuICAgIHZhciBkaWdlc3RUcml0cyA9IENvbnZlcnRlci50cml0cyhkaWdlc3RzW2ldKTtcblxuICAgIC8vIEFic29yYiBkaWdlc3RcbiAgICB0aGlzLl9rZXJsLmFic29yYihkaWdlc3RUcml0cywgMCwgZGlnZXN0VHJpdHMubGVuZ3RoKTtcbiAgfVxuXG4gIHJldHVybiB0aGlzO1xufVxuXG4vKipcbiogICBGaW5hbGl6ZXMgYW5kIHJldHVybnMgdGhlIG11bHRpc2lnIGFkZHJlc3MgaW4gdHJ5dGVzXG4qXG4qICAgQG1ldGhvZCBmaW5hbGl6ZVxuKiAgIEBwYXJhbSB7c3RyaW5nfSBkaWdlc3QgZGlnZXN0IHRyeXRlcywgb3B0aW9uYWxcbiogICBAcmV0dXJuIHtzdHJpbmd9IGFkZHJlc3MgdHJ5dGVzXG4qXG4qKi9cbkFkZHJlc3MucHJvdG90eXBlLmZpbmFsaXplID0gZnVuY3Rpb24gKGRpZ2VzdCkge1xuXG4gICAgLy8gQWJzb3JiIGxhc3QgZGlnZXN0IGlmIHByb3ZpZGVkXG4gICAgaWYgKGRpZ2VzdCkge1xuICAgICAgdGhpcy5hYnNvcmIoZGlnZXN0KTtcbiAgICB9XG5cbiAgICAvLyBTcXVlZXplIHRoZSBhZGRyZXNzIHRyaXRzXG4gICAgdmFyIGFkZHJlc3NUcml0cyA9IFtdO1xuICAgIHRoaXMuX2tlcmwuc3F1ZWV6ZShhZGRyZXNzVHJpdHMsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuXG4gICAgLy8gQ29udmVydCB0cml0cyBpbnRvIHRyeXRlcyBhbmQgcmV0dXJuIHRoZSBhZGRyZXNzXG4gICAgcmV0dXJuIENvbnZlcnRlci50cnl0ZXMoYWRkcmVzc1RyaXRzKTtcbn1cblxuXG5tb2R1bGUuZXhwb3J0cyA9IEFkZHJlc3M7XG4iLCJ2YXIgU2lnbmluZyAgICAgICAgID0gIHJlcXVpcmUoJy4uL2NyeXB0by9zaWduaW5nL3NpZ25pbmcnKTtcbnZhciBDb252ZXJ0ZXIgICAgICAgPSAgcmVxdWlyZSgnLi4vY3J5cHRvL2NvbnZlcnRlci9jb252ZXJ0ZXInKTtcbnZhciBLZXJsICAgICAgICAgICAgPSAgcmVxdWlyZSgnLi4vY3J5cHRvL2tlcmwva2VybCcpO1xudmFyIEN1cmwgICAgICAgICAgICA9ICByZXF1aXJlKCcuLi9jcnlwdG8vY3VybC9jdXJsJyk7XG52YXIgQnVuZGxlICAgICAgICAgID0gIHJlcXVpcmUoJy4uL2NyeXB0by9idW5kbGUvYnVuZGxlJyk7XG52YXIgVXRpbHMgICAgICAgICAgID0gIHJlcXVpcmUoJy4uL3V0aWxzL3V0aWxzJyk7XG52YXIgaW5wdXRWYWxpZGF0b3IgID0gIHJlcXVpcmUoJy4uL3V0aWxzL2lucHV0VmFsaWRhdG9yJyk7XG52YXIgZXJyb3JzICAgICAgICAgID0gIHJlcXVpcmUoJy4uL2Vycm9ycy9pbnB1dEVycm9ycycpO1xudmFyIEFkZHJlc3MgICAgICAgICA9ICByZXF1aXJlKCcuL2FkZHJlc3MnKTtcblxuZnVuY3Rpb24gTXVsdGlzaWcocHJvdmlkZXIpIHtcblxuICAgIHRoaXMuX21ha2VSZXF1ZXN0ID0gcHJvdmlkZXI7XG59XG5cblxuLyoqXG4qICAgR2V0cyB0aGUga2V5IHZhbHVlIG9mIGEgc2VlZFxuKlxuKiAgIEBtZXRob2QgZ2V0S2V5XG4qICAgQHBhcmFtIHtzdHJpbmd9IHNlZWRcbiogICBAcGFyYW0ge2ludH0gaW5kZXhcbiogICBAcGFyYW0ge2ludH0gc2VjdXJpdHkgU2VjdXJpdHkgbGV2ZWwgdG8gYmUgdXNlZCBmb3IgdGhlIHByaXZhdGUga2V5IC8gYWRkcmVzcy4gQ2FuIGJlIDEsIDIgb3IgM1xuKiAgIEByZXR1cm5zIHtzdHJpbmd9IGRpZ2VzdCB0cnl0ZXNcbioqL1xuTXVsdGlzaWcuZ2V0S2V5ID0gZnVuY3Rpb24oc2VlZCwgaW5kZXgsIHNlY3VyaXR5KSB7XG5cbiAgICByZXR1cm4gQ29udmVydGVyLnRyeXRlcyhTaWduaW5nLmtleShDb252ZXJ0ZXIudHJpdHMoc2VlZCksIGluZGV4LCBzZWN1cml0eSkpO1xufVxuXG4vKipcbiogICBHZXRzIHRoZSBkaWdlc3QgdmFsdWUgb2YgYSBzZWVkXG4qXG4qICAgQG1ldGhvZCBnZXREaWdlc3RcbiogICBAcGFyYW0ge3N0cmluZ30gc2VlZFxuKiAgIEBwYXJhbSB7aW50fSBpbmRleFxuKiAgIEBwYXJhbSB7aW50fSBzZWN1cml0eSBTZWN1cml0eSBsZXZlbCB0byBiZSB1c2VkIGZvciB0aGUgcHJpdmF0ZSBrZXkgLyBhZGRyZXNzLiBDYW4gYmUgMSwgMiBvciAzXG4qICAgQHJldHVybnMge3N0cmluZ30gZGlnZXN0IHRyeXRlc1xuKiovXG5NdWx0aXNpZy5nZXREaWdlc3QgPSBmdW5jdGlvbihzZWVkLCBpbmRleCwgc2VjdXJpdHkpIHtcblxuICAgIHZhciBrZXkgPSBTaWduaW5nLmtleShDb252ZXJ0ZXIudHJpdHMoc2VlZCksIGluZGV4LCBzZWN1cml0eSk7XG4gICAgcmV0dXJuIENvbnZlcnRlci50cnl0ZXMoU2lnbmluZy5kaWdlc3RzKGtleSkpO1xufVxuXG4vKipcbiogICBNdWx0aXNpZyBhZGRyZXNzIGNvbnN0cnVjdG9yXG4qL1xuTXVsdGlzaWcuYWRkcmVzcyA9IEFkZHJlc3M7XG5cbi8qKlxuKiAgIFZhbGlkYXRlcyAgYSBnZW5lcmF0ZWQgbXVsdGlzaWcgYWRkcmVzc1xuKlxuKiAgIEBtZXRob2QgdmFsaWRhdGVBZGRyZXNzXG4qICAgQHBhcmFtIHtzdHJpbmd9IG11bHRpc2lnQWRkcmVzc1xuKiAgIEBwYXJhbSB7YXJyYXl9IGRpZ2VzdHNcbiogICBAcmV0dXJucyB7Ym9vbH1cbioqL1xuTXVsdGlzaWcudmFsaWRhdGVBZGRyZXNzID0gZnVuY3Rpb24obXVsdGlzaWdBZGRyZXNzLCBkaWdlc3RzKSB7XG5cbiAgICB2YXIga2VybCA9IG5ldyBLZXJsKCk7XG5cbiAgICAvLyBpbml0aWFsaXplIEtlcmwgd2l0aCB0aGUgcHJvdmlkZWQgc3RhdGVcbiAgICBrZXJsLmluaXRpYWxpemUoKTtcblxuICAgIC8vIEFic29yYiBhbGwga2V5IGRpZ2VzdHNcbiAgICBkaWdlc3RzLmZvckVhY2goZnVuY3Rpb24oa2V5RGlnZXN0KSB7XG4gICAgICAgIHZhciB0cml0cyA9IENvbnZlcnRlci50cml0cyhrZXlEaWdlc3QpO1xuICAgICAgICBrZXJsLmFic29yYihDb252ZXJ0ZXIudHJpdHMoa2V5RGlnZXN0KSwgMCwgdHJpdHMubGVuZ3RoKTtcbiAgICB9KVxuXG4gICAgLy8gU3F1ZWV6ZSBhZGRyZXNzIHRyaXRzXG4gICAgdmFyIGFkZHJlc3NUcml0cyA9IFtdO1xuICAgIGtlcmwuc3F1ZWV6ZShhZGRyZXNzVHJpdHMsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuXG4gICAgLy8gQ29udmVydCB0cml0cyBpbnRvIHRyeXRlcyBhbmQgcmV0dXJuIHRoZSBhZGRyZXNzXG4gICAgcmV0dXJuIENvbnZlcnRlci50cnl0ZXMoYWRkcmVzc1RyaXRzKSA9PT0gbXVsdGlzaWdBZGRyZXNzO1xufVxuXG5cbi8qKlxuKiAgIFByZXBhcmVzIHRyYW5zZmVyIGJ5IGdlbmVyYXRpbmcgdGhlIGJ1bmRsZSB3aXRoIHRoZSBjb3JyZXNwb25kaW5nIGNvc2lnbmVyIHRyYW5zYWN0aW9uc1xuKiAgIERvZXMgbm90IGNvbnRhaW4gc2lnbmF0dXJlc1xuKlxuKiAgIEBtZXRob2QgaW5pdGlhdGVUcmFuc2ZlclxuKiAgIEBwYXJhbSB7b2JqZWN0fSBpbnB1dCB0aGUgaW5wdXQgYWRkcmVzc2VzIGFzIHdlbGwgYXMgdGhlIHNlY3VyaXR5U3VtLCBhbmQgYmFsYW5jZVxuKiAgICAgICAgICAgICAgICAgICB3aGVyZSBgYWRkcmVzc2AgaXMgdGhlIGlucHV0IG11bHRpc2lnIGFkZHJlc3NcbiogICAgICAgICAgICAgICAgICAgYW5kIGBzZWN1cml0eVN1bWAgaXMgdGhlIHN1bSBvZiBzZWN1cml0eSBsZXZlbHMgdXNlZCBieSBhbGwgY28tc2lnbmVyc1xuKiAgICAgICAgICAgICAgICAgICBhbmQgYGJhbGFuY2VgIGlzIHRoZSBleHBlY3RlZCBiYWxhbmNlLCBpZiB5b3Ugd2lzaCB0byBvdmVycmlkZSBnZXRCYWxhbmNlc1xuKiAgIEBwYXJhbSB7c3RyaW5nfSByZW1haW5kZXJBZGRyZXNzIEhhcyB0byBiZSBnZW5lcmF0ZWQgYnkgdGhlIGNvc2lnbmVycyBiZWZvcmUgaW5pdGlhdGluZyB0aGUgdHJhbnNmZXIsIGNhbiBiZSBudWxsIGlmIGZ1bGx5IHNwZW50XG4qICAgQHBhcmFtIHtvYmplY3R9IHRyYW5zZmVyc1xuKiAgIEBwYXJhbSB7ZnVuY3Rpb259IGNhbGxiYWNrXG4qICAgQHJldHVybnMge2FycmF5fSBBcnJheSBvZiB0cmFuc2FjdGlvbiBvYmplY3RzXG4qKi9cbk11bHRpc2lnLmluaXRpYXRlVHJhbnNmZXIgPSBmdW5jdGlvbihpbnB1dCwgcmVtYWluZGVyQWRkcmVzcywgdHJhbnNmZXJzLCBjYWxsYmFjaykge1xuXG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuXG4gICAgLy8gSWYgbWVzc2FnZSBvciB0YWcgaXMgbm90IHN1cHBsaWVkLCBwcm92aWRlIGl0XG4gICAgLy8gQWxzbyByZW1vdmUgdGhlIGNoZWNrc3VtIG9mIHRoZSBhZGRyZXNzIGlmIGl0J3MgdGhlcmVcbiAgICB0cmFuc2ZlcnMuZm9yRWFjaChmdW5jdGlvbih0aGlzVHJhbnNmZXIpIHtcbiAgICAgICAgdGhpc1RyYW5zZmVyLm1lc3NhZ2UgPSB0aGlzVHJhbnNmZXIubWVzc2FnZSA/IHRoaXNUcmFuc2Zlci5tZXNzYWdlIDogJyc7XG4gICAgICAgIHRoaXNUcmFuc2Zlci50YWcgPSB0aGlzVHJhbnNmZXIudGFnID8gdGhpc1RyYW5zZmVyLnRhZyA6ICcnO1xuICAgICAgICB0aGlzVHJhbnNmZXIub2Jzb2xldGVUYWcgPSB0aGlzVHJhbnNmZXIub2Jzb2xldGVUYWcgPyB0aGlzVHJhbnNmZXIub2Jzb2xldGVUYWcgOiAnJzsgICAgICAgIFxuICAgICAgICB0aGlzVHJhbnNmZXIuYWRkcmVzcyA9IFV0aWxzLm5vQ2hlY2tzdW0odGhpc1RyYW5zZmVyLmFkZHJlc3MpO1xuICAgIH0pXG5cbiAgICAvLyBJbnB1dCB2YWxpZGF0aW9uIG9mIHRyYW5zZmVycyBvYmplY3RcbiAgICBpZiAoIWlucHV0VmFsaWRhdG9yLmlzVHJhbnNmZXJzQXJyYXkodHJhbnNmZXJzKSkge1xuICAgICAgICByZXR1cm4gY2FsbGJhY2soZXJyb3JzLmludmFsaWRUcmFuc2ZlcnMoKSk7XG4gICAgfVxuXG4gICAgLy8gY2hlY2sgaWYgaW50XG4gICAgaWYgKCFpbnB1dFZhbGlkYXRvci5pc1ZhbHVlKGlucHV0LnNlY3VyaXR5U3VtKSkge1xuICAgICAgICByZXR1cm4gY2FsbGJhY2soZXJyb3JzLmludmFsaWRJbnB1dHMoKSk7XG4gICAgfVxuXG4gICAgLy8gdmFsaWRhdGUgaW5wdXQgYWRkcmVzc1xuICAgIGlmICghaW5wdXRWYWxpZGF0b3IuaXNBZGRyZXNzKGlucHV0LmFkZHJlc3MpKSB7XG4gICAgICAgIHJldHVybiBjYWxsYmFjayhlcnJvcnMuaW52YWxpZFRyeXRlcygpKTtcbiAgICB9XG5cbiAgICAvLyB2YWxpZGF0ZSByZW1haW5kZXIgYWRkcmVzc1xuICAgIGlmIChyZW1haW5kZXJBZGRyZXNzICYmICFpbnB1dFZhbGlkYXRvci5pc0FkZHJlc3MocmVtYWluZGVyQWRkcmVzcykpIHtcbiAgICAgICAgcmV0dXJuIGNhbGxiYWNrKGVycm9ycy5pbnZhbGlkVHJ5dGVzKCkpO1xuICAgIH1cblxuICAgIC8vIENyZWF0ZSBhIG5ldyBidW5kbGVcbiAgICB2YXIgYnVuZGxlID0gbmV3IEJ1bmRsZSgpO1xuXG4gICAgdmFyIHRvdGFsVmFsdWUgPSAwO1xuICAgIHZhciBzaWduYXR1cmVGcmFnbWVudHMgPSBbXTtcbiAgICB2YXIgdGFnO1xuXG4gICAgLy9cbiAgICAvLyAgSXRlcmF0ZSBvdmVyIGFsbCB0cmFuc2ZlcnMsIGdldCB0b3RhbFZhbHVlXG4gICAgLy8gIGFuZCBwcmVwYXJlIHRoZSBzaWduYXR1cmVGcmFnbWVudHMsIG1lc3NhZ2UgYW5kIHRhZ1xuICAgIC8vXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0cmFuc2ZlcnMubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICB2YXIgc2lnbmF0dXJlTWVzc2FnZUxlbmd0aCA9IDE7XG5cbiAgICAgICAgLy8gSWYgbWVzc2FnZSBsb25nZXIgdGhhbiAyMTg3IHRyeXRlcywgaW5jcmVhc2Ugc2lnbmF0dXJlTWVzc2FnZUxlbmd0aCAoYWRkIG11bHRpcGxlIHRyYW5zYWN0aW9ucylcbiAgICAgICAgaWYgKHRyYW5zZmVyc1tpXS5tZXNzYWdlLmxlbmd0aCA+IDIxODcpIHtcblxuICAgICAgICAgICAgLy8gR2V0IHRvdGFsIGxlbmd0aCwgbWVzc2FnZSAvIG1heExlbmd0aCAoMjE4NyB0cnl0ZXMpXG4gICAgICAgICAgICBzaWduYXR1cmVNZXNzYWdlTGVuZ3RoICs9IE1hdGguZmxvb3IodHJhbnNmZXJzW2ldLm1lc3NhZ2UubGVuZ3RoIC8gMjE4Nyk7XG5cbiAgICAgICAgICAgIHZhciBtc2dDb3B5ID0gdHJhbnNmZXJzW2ldLm1lc3NhZ2U7XG5cbiAgICAgICAgICAgIC8vIFdoaWxlIHRoZXJlIGlzIHN0aWxsIGEgbWVzc2FnZSwgY29weSBpdFxuICAgICAgICAgICAgd2hpbGUgKG1zZ0NvcHkpIHtcblxuICAgICAgICAgICAgICAgIHZhciBmcmFnbWVudCA9IG1zZ0NvcHkuc2xpY2UoMCwgMjE4Nyk7XG4gICAgICAgICAgICAgICAgbXNnQ29weSA9IG1zZ0NvcHkuc2xpY2UoMjE4NywgbXNnQ29weS5sZW5ndGgpO1xuXG4gICAgICAgICAgICAgICAgLy8gUGFkIHJlbWFpbmRlciBvZiBmcmFnbWVudFxuICAgICAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBmcmFnbWVudC5sZW5ndGggPCAyMTg3OyBqKyspIHtcbiAgICAgICAgICAgICAgICAgICAgZnJhZ21lbnQgKz0gJzknO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIHNpZ25hdHVyZUZyYWdtZW50cy5wdXNoKGZyYWdtZW50KTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgLy8gRWxzZSwgZ2V0IHNpbmdsZSBmcmFnbWVudCB3aXRoIDIxODcgb2YgOSdzIHRyeXRlc1xuICAgICAgICAgICAgdmFyIGZyYWdtZW50ID0gJyc7XG5cbiAgICAgICAgICAgIGlmICh0cmFuc2ZlcnNbaV0ubWVzc2FnZSkge1xuICAgICAgICAgICAgICAgIGZyYWdtZW50ID0gdHJhbnNmZXJzW2ldLm1lc3NhZ2Uuc2xpY2UoMCwgMjE4NylcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZm9yICh2YXIgaiA9IDA7IGZyYWdtZW50Lmxlbmd0aCA8IDIxODc7IGorKykge1xuICAgICAgICAgICAgICAgIGZyYWdtZW50ICs9ICc5JztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgc2lnbmF0dXJlRnJhZ21lbnRzLnB1c2goZnJhZ21lbnQpO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gZ2V0IGN1cnJlbnQgdGltZXN0YW1wIGluIHNlY29uZHNcbiAgICAgICAgdmFyIHRpbWVzdGFtcCA9IE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDEwMDApO1xuXG4gICAgICAgIC8vIElmIG5vIHRhZyBkZWZpbmVkLCBnZXQgMjcgdHJ5dGUgdGFnLlxuICAgICAgICB0YWcgPSB0cmFuc2ZlcnNbaV0udGFnID8gdHJhbnNmZXJzW2ldLnRhZyA6ICc5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTknO1xuXG4gICAgICAgIC8vIFBhZCBmb3IgcmVxdWlyZWQgMjcgdHJ5dGUgbGVuZ3RoXG4gICAgICAgIGZvciAodmFyIGogPSAwOyB0YWcubGVuZ3RoIDwgMjc7IGorKykge1xuICAgICAgICAgICAgdGFnICs9ICc5JztcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIEFkZCBmaXJzdCBlbnRyaWVzIHRvIHRoZSBidW5kbGVcbiAgICAgICAgLy8gU2xpY2UgdGhlIGFkZHJlc3MgaW4gY2FzZSB0aGUgdXNlciBwcm92aWRlZCBhIGNoZWNrc3VtbWVkIG9uZVxuICAgICAgICBidW5kbGUuYWRkRW50cnkoc2lnbmF0dXJlTWVzc2FnZUxlbmd0aCwgdHJhbnNmZXJzW2ldLmFkZHJlc3Muc2xpY2UoMCwgODEpLCB0cmFuc2ZlcnNbaV0udmFsdWUsIHRhZywgdGltZXN0YW1wKTtcblxuICAgICAgICAvLyBTdW0gdXAgdG90YWwgdmFsdWVcbiAgICAgICAgdG90YWxWYWx1ZSArPSBwYXJzZUludCh0cmFuc2ZlcnNbaV0udmFsdWUpO1xuICAgIH1cblxuICAgIC8vIEdldCBpbnB1dHMgaWYgd2UgYXJlIHNlbmRpbmcgdG9rZW5zXG4gICAgaWYgKHRvdGFsVmFsdWUpIHtcblxuICAgICAgICBmdW5jdGlvbiBjcmVhdGVCdW5kbGUodG90YWxCYWxhbmNlLCBjYWxsYmFjaykge1xuICAgICAgICAgICAgaWYgKHRvdGFsQmFsYW5jZSA+IDApIHtcblxuICAgICAgICAgICAgICAgIHZhciB0b1N1YnRyYWN0ID0gMCAtIHRvdGFsQmFsYW5jZTtcbiAgICAgICAgICAgICAgICB2YXIgdGltZXN0YW1wID0gTWF0aC5mbG9vcihEYXRlLm5vdygpIC8gMTAwMCk7XG5cbiAgICAgICAgICAgICAgICAvLyBBZGQgaW5wdXQgYXMgYnVuZGxlIGVudHJ5XG4gICAgICAgICAgICAgICAgLy8gT25seSBhIHNpbmdsZSBlbnRyeSwgc2lnbmF0dXJlcyB3aWxsIGJlIGFkZGVkIGxhdGVyXG4gICAgICAgICAgICAgICAgYnVuZGxlLmFkZEVudHJ5KGlucHV0LnNlY3VyaXR5U3VtLCBpbnB1dC5hZGRyZXNzLCB0b1N1YnRyYWN0LCB0YWcsIHRpbWVzdGFtcCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICh0b3RhbFZhbHVlID4gdG90YWxCYWxhbmNlKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGNhbGxiYWNrKG5ldyBFcnJvcihcIk5vdCBlbm91Z2ggYmFsYW5jZS5cIikpO1xuICAgICAgICAgICAgfVxuXG5cbiAgICAgICAgICAgIC8vIElmIHRoZXJlIGlzIGEgcmVtYWluZGVyIHZhbHVlXG4gICAgICAgICAgICAvLyBBZGQgZXh0cmEgb3V0cHV0IHRvIHNlbmQgcmVtYWluaW5nIGZ1bmRzIHRvXG4gICAgICAgICAgICBpZiAodG90YWxCYWxhbmNlID4gdG90YWxWYWx1ZSkge1xuXG4gICAgICAgICAgICAgICAgdmFyIHJlbWFpbmRlciA9IHRvdGFsQmFsYW5jZSAtIHRvdGFsVmFsdWU7XG5cbiAgICAgICAgICAgICAgICAvLyBSZW1haW5kZXIgYnVuZGxlIGVudHJ5IGlmIG5lY2Vzc2FyeVxuICAgICAgICAgICAgICAgIGlmICghcmVtYWluZGVyQWRkcmVzcykge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gY2FsbGJhY2sobmV3IEVycm9yKFwiTm8gcmVtYWluZGVyIGFkZHJlc3MgZGVmaW5lZFwiKSk7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgYnVuZGxlLmFkZEVudHJ5KDEsIHJlbWFpbmRlckFkZHJlc3MsIHJlbWFpbmRlciwgdGFnLCB0aW1lc3RhbXApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBidW5kbGUuZmluYWxpemUoKTtcbiAgICAgICAgICAgIGJ1bmRsZS5hZGRUcnl0ZXMoc2lnbmF0dXJlRnJhZ21lbnRzKTtcblxuICAgICAgICAgICAgcmV0dXJuIGNhbGxiYWNrKG51bGwsIGJ1bmRsZS5idW5kbGUpO1xuICAgICAgICB9O1xuXG4gICAgICAgIGlmIChpbnB1dC5iYWxhbmNlKSB7XG4gICAgICAgICAgY3JlYXRlQnVuZGxlKGlucHV0LmJhbGFuY2UsIGNhbGxiYWNrKTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICB2YXIgY29tbWFuZCA9IHtcbiAgICAgICAgICAgICAgJ2NvbW1hbmQnOiAnZ2V0QmFsYW5jZXMnLFxuICAgICAgICAgICAgICAnYWRkcmVzc2VzJzogbmV3IEFycmF5KGlucHV0LmFkZHJlc3MpLFxuICAgICAgICAgICAgICAndGhyZXNob2xkJzogMTAwXG4gICAgICAgICAgfVxuICAgICAgICAgIHNlbGYuX21ha2VSZXF1ZXN0LnNlbmQoY29tbWFuZCwgZnVuY3Rpb24oZSwgYmFsYW5jZXMpIHtcbiAgICAgICAgICAgICAgaWYgKGUpIHJldHVybiBjYWxsYmFjayhlKTtcbiAgICAgICAgICAgICAgY3JlYXRlQnVuZGxlKHBhcnNlSW50KGJhbGFuY2VzLmJhbGFuY2VzWzBdKSwgY2FsbGJhY2spO1xuICAgICAgICAgIH0pO1xuICAgICAgICB9XG5cbiAgICB9IGVsc2Uge1xuXG4gICAgICAgIHJldHVybiBjYWxsYmFjayhuZXcgRXJyb3IoXCJJbnZhbGlkIHZhbHVlIHRyYW5zZmVyOiB0aGUgdHJhbnNmZXIgZG9lcyBub3QgcmVxdWlyZSBhIHNpZ25hdHVyZS5cIikpO1xuICAgIH1cblxufVxuXG5cbi8qKlxuKiAgIEFkZHMgdGhlIGNvc2lnbmVyIHNpZ25hdHVyZXMgdG8gdGhlIGNvcnJlc3BvbmRpbmcgYnVuZGxlIHRyYW5zYWN0aW9uXG4qXG4qICAgQG1ldGhvZCBhZGRTaWduYXR1cmVcbiogICBAcGFyYW0ge2FycmF5fSBidW5kbGVUb1NpZ25cbiogICBAcGFyYW0ge2ludH0gY29zaWduZXJJbmRleFxuKiAgIEBwYXJhbSB7c3RyaW5nfSBpbnB1dEFkZHJlc3NcbiogICBAcGFyYW0ge3N0cmluZ30ga2V5XG4qICAgQHBhcmFtIHtmdW5jdGlvbn0gY2FsbGJhY2tcbiogICBAcmV0dXJucyB7YXJyYXl9IHRyeXRlcyBSZXR1cm5zIGJ1bmRsZSB0cnl0ZXNcbioqL1xuTXVsdGlzaWcuYWRkU2lnbmF0dXJlID0gZnVuY3Rpb24oYnVuZGxlVG9TaWduLCBpbnB1dEFkZHJlc3MsIGtleSwgY2FsbGJhY2spIHtcblxuICAgIHZhciBidW5kbGUgPSBuZXcgQnVuZGxlKCk7XG4gICAgYnVuZGxlLmJ1bmRsZSA9IGJ1bmRsZVRvU2lnbjtcblxuICAgIC8vIEdldCB0aGUgc2VjdXJpdHkgdXNlZCBmb3IgdGhlIHByaXZhdGUga2V5XG4gICAgLy8gMSBzZWN1cml0eSBsZXZlbCA9IDIxODcgdHJ5dGVzXG4gICAgdmFyIHNlY3VyaXR5ID0gKGtleS5sZW5ndGggLyAyMTg3KTtcblxuICAgIC8vIGNvbnZlcnQgcHJpdmF0ZSBrZXkgdHJ5dGVzIGludG8gdHJpdHNcbiAgICB2YXIga2V5ID0gQ29udmVydGVyLnRyaXRzKGtleSk7XG5cblxuICAgIC8vIEZpcnN0IGdldCB0aGUgdG90YWwgbnVtYmVyIG9mIGFscmVhZHkgc2lnbmVkIHRyYW5zYWN0aW9uc1xuICAgIC8vIHVzZSB0aGF0IGZvciB0aGUgYnVuZGxlIGhhc2ggY2FsY3VsYXRpb24gYXMgd2VsbCBhcyBrbm93aW5nXG4gICAgLy8gd2hlcmUgdG8gYWRkIHRoZSBzaWduYXR1cmVcbiAgICB2YXIgbnVtU2lnbmVkVHhzID0gMDtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnVuZGxlLmJ1bmRsZS5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIGlmIChidW5kbGUuYnVuZGxlW2ldLmFkZHJlc3MgPT09IGlucHV0QWRkcmVzcykge1xuXG4gICAgICAgICAgICAvLyBJZiB0cmFuc2FjdGlvbiBpcyBhbHJlYWR5IHNpZ25lZCwgaW5jcmVhc2UgY291bnRlclxuICAgICAgICAgICAgaWYgKCFpbnB1dFZhbGlkYXRvci5pc05pbmVzVHJ5dGVzKGJ1bmRsZS5idW5kbGVbaV0uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50KSkge1xuXG4gICAgICAgICAgICAgICAgbnVtU2lnbmVkVHhzKys7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICAvLyBFbHNlIHNpZ24gdGhlIHRyYW5zYWN0aW9uc2VcbiAgICAgICAgICAgIGVsc2Uge1xuXG4gICAgICAgICAgICAgICAgdmFyIGJ1bmRsZUhhc2ggPSBidW5kbGUuYnVuZGxlW2ldLmJ1bmRsZTtcblxuICAgICAgICAgICAgICAgIC8vICBGaXJzdCA2NTYxIHRyaXRzIGZvciB0aGUgZmlyc3RGcmFnbWVudFxuICAgICAgICAgICAgICAgIHZhciBmaXJzdEZyYWdtZW50ID0ga2V5LnNsaWNlKDAsIDY1NjEpO1xuXG4gICAgICAgICAgICAgICAgLy8gIEdldCB0aGUgbm9ybWFsaXplZCBidW5kbGUgaGFzaFxuICAgICAgICAgICAgICAgIHZhciBub3JtYWxpemVkQnVuZGxlSGFzaCA9IGJ1bmRsZS5ub3JtYWxpemVkQnVuZGxlKGJ1bmRsZUhhc2gpO1xuICAgICAgICAgICAgICAgIHZhciBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRzID0gW107XG5cbiAgICAgICAgICAgICAgICAvLyBTcGxpdCBoYXNoIGludG8gMyBmcmFnbWVudHNcbiAgICAgICAgICAgICAgICBmb3IgKHZhciBrID0gMDsgayA8IDM7IGsrKykge1xuICAgICAgICAgICAgICAgICAgICBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRzW2tdID0gbm9ybWFsaXplZEJ1bmRsZUhhc2guc2xpY2UoayAqIDI3LCAoayArIDEpICogMjcpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIC8vICBGaXJzdCBidW5kbGUgZnJhZ21lbnQgdXNlcyAyNyB0cnl0ZXNcbiAgICAgICAgICAgICAgICB2YXIgZmlyc3RCdW5kbGVGcmFnbWVudCA9IG5vcm1hbGl6ZWRCdW5kbGVGcmFnbWVudHNbbnVtU2lnbmVkVHhzICUgM107XG5cbiAgICAgICAgICAgICAgICAvLyAgQ2FsY3VsYXRlIHRoZSBuZXcgc2lnbmF0dXJlRnJhZ21lbnQgd2l0aCB0aGUgZmlyc3QgYnVuZGxlIGZyYWdtZW50XG4gICAgICAgICAgICAgICAgdmFyIGZpcnN0U2lnbmVkRnJhZ21lbnQgPSBTaWduaW5nLnNpZ25hdHVyZUZyYWdtZW50KGZpcnN0QnVuZGxlRnJhZ21lbnQsIGZpcnN0RnJhZ21lbnQpO1xuXG4gICAgICAgICAgICAgICAgLy8gIENvbnZlcnQgc2lnbmF0dXJlIHRvIHRyeXRlcyBhbmQgYXNzaWduIHRoZSBuZXcgc2lnbmF0dXJlRnJhZ21lbnRcbiAgICAgICAgICAgICAgICBidW5kbGUuYnVuZGxlW2ldLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudCA9IENvbnZlcnRlci50cnl0ZXMoZmlyc3RTaWduZWRGcmFnbWVudCk7XG5cbiAgICAgICAgICAgICAgICBmb3IgKHZhciBqID0gMTsgaiA8IHNlY3VyaXR5OyBqKyspIHtcblxuICAgICAgICAgICAgICAgICAgICAvLyAgTmV4dCA2NTYxIHRyaXRzIGZvciB0aGUgZmlyc3RGcmFnbWVudFxuICAgICAgICAgICAgICAgICAgICB2YXIgbmV4dEZyYWdtZW50ID0ga2V5LnNsaWNlKDY1NjEgKiBqLCAoaiArIDEpICogNjU2MSk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gIFVzZSB0aGUgbmV4dCAyNyB0cnl0ZXNcbiAgICAgICAgICAgICAgICAgICAgdmFyIG5leHRCdW5kbGVGcmFnbWVudCA9IG5vcm1hbGl6ZWRCdW5kbGVGcmFnbWVudHNbKG51bVNpZ25lZFR4cyArIGopICUgM107XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gIENhbGN1bGF0ZSB0aGUgbmV3IHNpZ25hdHVyZUZyYWdtZW50IHdpdGggdGhlIGZpcnN0IGJ1bmRsZSBmcmFnbWVudFxuICAgICAgICAgICAgICAgICAgICB2YXIgbmV4dFNpZ25lZEZyYWdtZW50ID0gU2lnbmluZy5zaWduYXR1cmVGcmFnbWVudChuZXh0QnVuZGxlRnJhZ21lbnQsIG5leHRGcmFnbWVudCk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gIENvbnZlcnQgc2lnbmF0dXJlIHRvIHRyeXRlcyBhbmQgYWRkIG5ldyBidW5kbGUgZW50cnkgYXQgaSArIGogcG9zaXRpb25cbiAgICAgICAgICAgICAgICAgICAgLy8gQXNzaWduIHRoZSBzaWduYXR1cmUgZnJhZ21lbnRcbiAgICAgICAgICAgICAgICAgICAgYnVuZGxlLmJ1bmRsZVtpICsgal0uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50ID0gQ29udmVydGVyLnRyeXRlcyhuZXh0U2lnbmVkRnJhZ21lbnQpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIGNhbGxiYWNrKG51bGwsIGJ1bmRsZS5idW5kbGUpO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IE11bHRpc2lnO1xuIiwiLy9cbi8vICBDb252ZXJzaW9uIG9mIGFzY2lpIGVuY29kZWQgYnl0ZXMgdG8gdHJ5dGVzLlxuLy8gIElucHV0IGlzIGEgc3RyaW5nIChjYW4gYmUgc3RyaW5naWZpZWQgSlNPTiBvYmplY3QpLCByZXR1cm4gdmFsdWUgaXMgVHJ5dGVzXG4vL1xuLy8gIEhvdyB0aGUgY29udmVyc2lvbiB3b3Jrczpcbi8vICAgIDIgVHJ5dGVzID09PSAxIEJ5dGVcbi8vICAgIFRoZXJlIGFyZSBhIHRvdGFsIG9mIDI3IGRpZmZlcmVudCB0cnl0ZSB2YWx1ZXM6IDlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWlxuLy9cbi8vICAgIDEuIFdlIGdldCB0aGUgZGVjaW1hbCB2YWx1ZSBvZiBhbiBpbmRpdmlkdWFsIEFTQ0lJIGNoYXJhY3RlclxuLy8gICAgMi4gRnJvbSB0aGUgZGVjaW1hbCB2YWx1ZSwgd2UgdGhlbiBkZXJpdmUgdGhlIHR3byB0cnl0ZSB2YWx1ZXMgYnkgYmFzaWNhbGx5IGNhbGN1bGF0aW5nIHRoZSB0cnl0ZSBlcXVpdmFsZW50IChlLmcuIDEwMCA9PT0gMTkgKyAzICogMjcpXG4vLyAgICAgIGEuIFRoZSBmaXJzdCB0cnl0ZSB2YWx1ZSBpcyB0aGUgZGVjaW1hbCB2YWx1ZSBtb2R1bG8gMjcgKDI3IHRyeXRlcylcbi8vICAgICAgYi4gVGhlIHNlY29uZCB2YWx1ZSBpcyB0aGUgcmVtYWluZGVyIChkZWNpbWFsIHZhbHVlIC0gZmlyc3QgdmFsdWUpLCBkaXZpZGVkIGJ5IDI3XG4vLyAgICAzLiBUaGUgdHdvIHZhbHVlcyByZXR1cm5lZCBmcm9tIFN0ZXAgMi4gYXJlIHRoZW4gaW5wdXQgYXMgaW5kaWNlcyBpbnRvIHRoZSBhdmFpbGFibGUgdmFsdWVzIGxpc3QgKCc5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVonKSB0byBnZXQgdGhlIGNvcnJlY3QgdHJ5dGUgdmFsdWVcbi8vXG4vLyAgIEVYQU1QTEVTXG4vLyAgICAgIExldHMgc2F5IHdlIHdhbnQgdG8gY29udmVydCB0aGUgQVNDSUkgY2hhcmFjdGVyIFwiWlwiLlxuLy8gICAgICAgIDEuICdaJyBoYXMgYSBkZWNpbWFsIHZhbHVlIG9mIDkwLlxuLy8gICAgICAgIDIuIDkwIGNhbiBiZSByZXByZXNlbnRlZCBhcyA5ICsgMyAqIDI3LiBUbyBtYWtlIGl0IHNpbXBsZXI6XG4vLyAgICAgICAgICAgYS4gRmlyc3QgdmFsdWU6IDkwIG1vZHVsbyAyNyBpcyA5LiBUaGlzIGlzIG5vdyBvdXIgZmlyc3QgdmFsdWVcbi8vICAgICAgICAgICBiLiBTZWNvbmQgdmFsdWU6ICg5MCAtIDkpIC8gMjcgaXMgMy4gVGhpcyBpcyBvdXIgc2Vjb25kIHZhbHVlLlxuLy8gICAgICAgIDMuIE91ciB0d28gdmFsdWVzIGFyZSBub3cgOSBhbmQgMy4gVG8gZ2V0IHRoZSB0cnl0ZSB2YWx1ZSBub3cgd2Ugc2ltcGx5IGluc2VydCBpdCBhcyBpbmRpY2VzIGludG8gJzlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWidcbi8vICAgICAgICAgICBhLiBUaGUgZmlyc3QgdHJ5dGUgdmFsdWUgaXMgJzlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWidbOV0gPT09IFwiSVwiXG4vLyAgICAgICAgICAgYi4gVGhlIHNlY29uZCB0cnl0ZSB2YWx1ZSBpcyAnOUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaJ1szXSA9PT0gXCJDXCJcbi8vICAgICAgICBPdXIgdHJ5dGUgcGFpciBpcyBcIklDXCJcbi8vXG4vLyAgICAgIFJFU1VMVDpcbi8vICAgICAgICBUaGUgQVNDSUkgY2hhciBcIlpcIiBpcyByZXByZXNlbnRlZCBhcyBcIklDXCIgaW4gdHJ5dGVzLlxuLy9cbmZ1bmN0aW9uIHRvVHJ5dGVzKGlucHV0KSB7XG5cbiAgICAvLyBJZiBpbnB1dCBpcyBub3QgYSBzdHJpbmcsIHJldHVybiBudWxsXG4gICAgaWYgKCB0eXBlb2YgaW5wdXQgIT09ICdzdHJpbmcnICkgcmV0dXJuIG51bGxcblxuICAgIHZhciBUUllURV9WQUxVRVMgPSBcIjlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWlwiO1xuICAgIHZhciB0cnl0ZXMgPSBcIlwiO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBpbnB1dC5sZW5ndGg7IGkrKykge1xuICAgICAgICB2YXIgY2hhciA9IGlucHV0W2ldO1xuICAgICAgICB2YXIgYXNjaWlWYWx1ZSA9IGNoYXIuY2hhckNvZGVBdCgwKTtcblxuICAgICAgICAvLyBJZiBub3QgcmVjb2duaXphYmxlIEFTQ0lJIGNoYXJhY3RlciwgcmV0dXJuIG51bGxcbiAgICAgICAgaWYgKGFzY2lpVmFsdWUgPiAyNTUpIHtcbiAgICAgICAgICAgIC8vYXNjaWlWYWx1ZSA9IDMyXG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcbiAgICAgICAgfVxuXG4gICAgICAgIHZhciBmaXJzdFZhbHVlID0gYXNjaWlWYWx1ZSAlIDI3O1xuICAgICAgICB2YXIgc2Vjb25kVmFsdWUgPSAoYXNjaWlWYWx1ZSAtIGZpcnN0VmFsdWUpIC8gMjc7XG5cbiAgICAgICAgdmFyIHRyeXRlc1ZhbHVlID0gVFJZVEVfVkFMVUVTW2ZpcnN0VmFsdWVdICsgVFJZVEVfVkFMVUVTW3NlY29uZFZhbHVlXTtcblxuICAgICAgICB0cnl0ZXMgKz0gdHJ5dGVzVmFsdWU7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRyeXRlcztcbn1cblxuXG4vL1xuLy8gIFRyeXRlcyB0byBieXRlc1xuLy8gIFJldmVyc2Ugb3BlcmF0aW9uIGZyb20gdGhlIGJ5dGVUb1RyeXRlcyBmdW5jdGlvbiBpbiBzZW5kLmpzXG4vLyAgMiBUcnl0ZXMgPT0gMSBCeXRlXG4vLyAgV2UgYXNzdW1lIHRoYXQgdGhlIHRyeXRlcyBhcmUgYSBKU09OIGVuY29kZWQgb2JqZWN0IHRodXMgZm9yIG91ciBlbmNvZGluZzpcbi8vICAgIEZpcnN0IGNoYXJhY3RlciA9IHtcbi8vICAgIExhc3QgY2hhcmFjdGVyID0gfVxuLy8gICAgRXZlcnl0aGluZyBhZnRlciB0aGF0IGlzIDkncyBwYWRkaW5nXG4vL1xuZnVuY3Rpb24gZnJvbVRyeXRlcyhpbnB1dFRyeXRlcykge1xuXG4gICAgLy8gSWYgaW5wdXQgaXMgbm90IGEgc3RyaW5nLCByZXR1cm4gbnVsbFxuICAgIGlmICggdHlwZW9mIGlucHV0VHJ5dGVzICE9PSAnc3RyaW5nJyApIHJldHVybiBudWxsXG5cbiAgICAvLyBJZiBpbnB1dCBsZW5ndGggaXMgb2RkLCByZXR1cm4gbnVsbFxuICAgIGlmICggaW5wdXRUcnl0ZXMubGVuZ3RoICUgMiApIHJldHVybiBudWxsXG5cbiAgICB2YXIgVFJZVEVfVkFMVUVTID0gXCI5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpcIjtcbiAgICB2YXIgb3V0cHV0U3RyaW5nID0gXCJcIjtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaW5wdXRUcnl0ZXMubGVuZ3RoOyBpICs9IDIpIHtcbiAgICAgICAgLy8gZ2V0IGEgdHJ5dGVzIHBhaXJcbiAgICAgICAgdmFyIHRyeXRlcyA9IGlucHV0VHJ5dGVzW2ldICsgaW5wdXRUcnl0ZXNbaSArIDFdO1xuXG4gICAgICAgIHZhciBmaXJzdFZhbHVlID0gVFJZVEVfVkFMVUVTLmluZGV4T2YodHJ5dGVzWzBdKTtcbiAgICAgICAgdmFyIHNlY29uZFZhbHVlID0gVFJZVEVfVkFMVUVTLmluZGV4T2YodHJ5dGVzWzFdKTtcblxuICAgICAgICB2YXIgZGVjaW1hbFZhbHVlID0gZmlyc3RWYWx1ZSArIHNlY29uZFZhbHVlICogMjc7XG5cbiAgICAgICAgdmFyIGNoYXJhY3RlciA9IFN0cmluZy5mcm9tQ2hhckNvZGUoZGVjaW1hbFZhbHVlKTtcblxuICAgICAgICBvdXRwdXRTdHJpbmcgKz0gY2hhcmFjdGVyO1xuICAgIH1cblxuICAgIHJldHVybiBvdXRwdXRTdHJpbmc7XG59XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICAgIHRvVHJ5dGVzOiB0b1RyeXRlcyxcbiAgICBmcm9tVHJ5dGVzOiBmcm9tVHJ5dGVzXG59XG4iLCJ2YXIgYXNjaWkgPSByZXF1aXJlKFwiLi9hc2NpaVRvVHJ5dGVzXCIpO1xudmFyIGlucHV0VmFsaWRhdG9yID0gcmVxdWlyZShcIi4vaW5wdXRWYWxpZGF0b3JcIik7XG5cbi8qKlxuKiAgIGV4dHJhY3RKc29uIHRha2VzIGEgYnVuZGxlIGFzIGlucHV0IGFuZCBmcm9tIHRoZSBzaWduYXR1cmVNZXNzYWdlRnJhZ21lbnRzIGV4dHJhY3RzIHRoZSBjb3JyZWN0IEpTT05cbiogICBkYXRhIHdoaWNoIHdhcyBlbmNvZGVkIGFuZCBzZW50IHdpdGggdGhlIHRyYW5zYWN0aW9uLlxuKlxuKiAgIEBtZXRob2QgZXh0cmFjdEpzb25cbiogICBAcGFyYW0ge2FycmF5fSBidW5kbGVcbiogICBAcmV0dXJucyB7T2JqZWN0fVxuKiovXG5mdW5jdGlvbiBleHRyYWN0SnNvbihidW5kbGUpIHtcblxuICAgIC8vIGlmIHdyb25nIGlucHV0IHJldHVybiBudWxsXG4gICAgaWYgKCAhaW5wdXRWYWxpZGF0b3IuaXNBcnJheShidW5kbGUpIHx8IGJ1bmRsZVswXSA9PT0gdW5kZWZpbmVkICkgcmV0dXJuIG51bGw7XG5cblxuICAgIC8vIFNhbml0eSBjaGVjazogaWYgdGhlIGZpcnN0IHRyeXRlIHBhaXIgaXMgbm90IG9wZW5pbmcgYnJhY2tldCwgaXQncyBub3QgYSBtZXNzYWdlXG4gICAgdmFyIGZpcnN0VHJ5dGVQYWlyID0gYnVuZGxlWzBdLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudFswXSArIGJ1bmRsZVswXS5zaWduYXR1cmVNZXNzYWdlRnJhZ21lbnRbMV07XG5cbiAgICBpZiAoZmlyc3RUcnl0ZVBhaXIgIT09IFwiT0RcIikgcmV0dXJuIG51bGw7XG5cbiAgICB2YXIgaW5kZXggPSAwO1xuICAgIHZhciBub3RFbmRlZCA9IHRydWU7XG4gICAgdmFyIHRyeXRlc0NodW5rID0gJyc7XG4gICAgdmFyIHRyeXRlc0NoZWNrZWQgPSAwO1xuICAgIHZhciBwcmVsaW1pbmFyeVN0b3AgPSBmYWxzZTtcbiAgICB2YXIgZmluYWxKc29uID0gJyc7XG5cbiAgICB3aGlsZSAoaW5kZXggPCBidW5kbGUubGVuZ3RoICYmIG5vdEVuZGVkKSB7XG5cbiAgICAgICAgdmFyIG1lc3NhZ2VDaHVuayA9IGJ1bmRsZVtpbmRleF0uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50O1xuXG4gICAgICAgIC8vIFdlIGl0ZXJhdGUgb3ZlciB0aGUgbWVzc2FnZSBjaHVuaywgcmVhZGluZyA5IHRyeXRlcyBhdCBhIHRpbWVcbiAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBtZXNzYWdlQ2h1bmsubGVuZ3RoOyBpICs9IDkpIHtcblxuICAgICAgICAgICAgLy8gZ2V0IDkgdHJ5dGVzXG4gICAgICAgICAgICB2YXIgdHJ5dGVzID0gbWVzc2FnZUNodW5rLnNsaWNlKGksIGkgKyA5KTtcbiAgICAgICAgICAgIHRyeXRlc0NodW5rICs9IHRyeXRlcztcblxuICAgICAgICAgICAgLy8gR2V0IHRoZSB1cHBlciBsaW1pdCBvZiB0aGUgdHl0ZXMgdGhhdCBuZWVkIHRvIGJlIGNoZWNrZWRcbiAgICAgICAgICAgIC8vIGJlY2F1c2Ugd2Ugb25seSBjaGVjayAyIHRyeXRlcyBhdCBhIHRpbWUsIHRoZXJlIGlzIHNvbWV0aW1lcyBhIGxlZnRvdmVyXG4gICAgICAgICAgICB2YXIgdXBwZXJMaW1pdCA9IHRyeXRlc0NodW5rLmxlbmd0aCAtIHRyeXRlc0NodW5rLmxlbmd0aCAlIDI7XG5cbiAgICAgICAgICAgIHZhciB0cnl0ZXNUb0NoZWNrID0gdHJ5dGVzQ2h1bmsuc2xpY2UodHJ5dGVzQ2hlY2tlZCwgdXBwZXJMaW1pdCk7XG5cbiAgICAgICAgICAgIC8vIFdlIHJlYWQgMiB0cnl0ZXMgYXQgYSB0aW1lIGFuZCBjaGVjayBpZiBpdCBlcXVhbHMgdGhlIGNsb3NpbmcgYnJhY2tldCBjaGFyYWN0ZXJcbiAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgdHJ5dGVzVG9DaGVjay5sZW5ndGg7IGogKz0gMikge1xuXG4gICAgICAgICAgICAgICAgdmFyIHRyeXRlUGFpciA9IHRyeXRlc1RvQ2hlY2tbal0gKyB0cnl0ZXNUb0NoZWNrW2ogKyAxXTtcblxuICAgICAgICAgICAgICAgIC8vIElmIGNsb3NpbmcgYnJhY2tldCBjaGFyIHdhcyBmb3VuZCwgYW5kIHRoZXJlIGFyZSBvbmx5IHRyYWlsaW5nIDknc1xuICAgICAgICAgICAgICAgIC8vIHdlIHF1aXQgYW5kIHJlbW92ZSB0aGUgOSdzIGZyb20gdGhlIHRyeXRlc0NodW5rLlxuICAgICAgICAgICAgICAgIGlmICggcHJlbGltaW5hcnlTdG9wICYmIHRyeXRlUGFpciA9PT0gJzk5JyApIHtcblxuICAgICAgICAgICAgICAgICAgICBub3RFbmRlZCA9IGZhbHNlO1xuICAgICAgICAgICAgICAgICAgICAvLyBUT0RPOiBSZW1vdmUgdGhlIHRyYWlsaW5nIDkncyBmcm9tIHRyeXRlc0NodW5rXG4gICAgICAgICAgICAgICAgICAgIC8vdmFyIGNsb3NpbmdCcmFja2V0ID0gdHJ5dGVzVG9DaGVjay5pbmRleE9mKCdRRCcpICsgMTtcblxuICAgICAgICAgICAgICAgICAgICAvL3RyeXRlc0NodW5rID0gdHJ5dGVzQ2h1bmsuc2xpY2UoIDAsICggdHJ5dGVzQ2h1bmsubGVuZ3RoIC0gdHJ5dGVzVG9DaGVjay5sZW5ndGggKSArICggY2xvc2luZ0JyYWNrZXQgJSAyID09PSAwID8gY2xvc2luZ0JyYWNrZXQgOiBjbG9zaW5nQnJhY2tldCArIDEgKSApO1xuXG4gICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGZpbmFsSnNvbiArPSBhc2NpaS5mcm9tVHJ5dGVzKHRyeXRlUGFpcik7XG5cbiAgICAgICAgICAgICAgICAvLyBJZiB0cnl0ZSBwYWlyIGVxdWFscyBjbG9zaW5nIGJyYWNrZXQgY2hhciwgd2Ugc2V0IGEgcHJlbGltaW5hcnkgc3RvcFxuICAgICAgICAgICAgICAgIC8vIHRoZSBwcmVsaW1pbmFyeVN0b3AgaXMgdXNlZnVsIHdoZW4gd2UgaGF2ZSBhIG5lc3RlZCBKU09OIG9iamVjdFxuICAgICAgICAgICAgICAgIGlmICh0cnl0ZVBhaXIgPT09IFwiUURcIikge1xuICAgICAgICAgICAgICAgICAgICBwcmVsaW1pbmFyeVN0b3AgPSB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgaWYgKCFub3RFbmRlZClcbiAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgdHJ5dGVzQ2hlY2tlZCArPSB0cnl0ZXNUb0NoZWNrLmxlbmd0aDtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIElmIHdlIGhhdmUgbm90IHJlYWNoZWQgdGhlIGVuZCBvZiB0aGUgbWVzc2FnZSB5ZXQsIHdlIGNvbnRpbnVlIHdpdGggdGhlIG5leHRcbiAgICAgICAgLy8gdHJhbnNhY3Rpb24gaW4gdGhlIGJ1bmRsZVxuICAgICAgICBpbmRleCArPSAxO1xuXG4gICAgfVxuXG4gICAgLy8gSWYgd2UgZGlkIG5vdCBmaW5kIGFueSBKU09OLCByZXR1cm4gbnVsbFxuICAgIGlmIChub3RFbmRlZCkge1xuXG4gICAgICAgIHJldHVybiBudWxsO1xuXG4gICAgfSBlbHNlIHtcblxuICAgICAgICByZXR1cm4gZmluYWxKc29uO1xuXG4gICAgfVxufVxuXG5tb2R1bGUuZXhwb3J0cyA9IGV4dHJhY3RKc29uO1xuIiwiLyoqXG4qICAgY2hlY2tzIGlmIGlucHV0IGlzIGNvcnJlY3QgYWRkcmVzc1xuKlxuKiAgIEBtZXRob2QgaXNBZGRyZXNzXG4qICAgQHBhcmFtIHtzdHJpbmd9IGFkZHJlc3NcbiogICBAcmV0dXJucyB7Ym9vbGVhbn1cbioqL1xudmFyIGlzQWRkcmVzcyA9IGZ1bmN0aW9uKGFkZHJlc3MpIHtcbiAgICAvLyBUT0RPOiBJbiB0aGUgZnV0dXJlIGNoZWNrIGNoZWNrc3VtXG5cbiAgICAvLyBDaGVjayBpZiBhZGRyZXNzIHdpdGggY2hlY2tzdW1cbiAgICBpZiAoYWRkcmVzcy5sZW5ndGggPT09IDkwKSB7XG5cbiAgICAgICAgaWYgKCFpc1RyeXRlcyhhZGRyZXNzLCA5MCkpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgIH0gZWxzZSB7XG5cbiAgICAgICAgaWYgKCFpc1RyeXRlcyhhZGRyZXNzLCA4MSkpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xufVxuXG4vKipcbiogICBjaGVja3MgaWYgaW5wdXQgaXMgY29ycmVjdCB0cnl0ZXMgY29uc2lzdGluZyBvZiBBLVo5XG4qICAgb3B0aW9uYWxseSB2YWxpZGF0ZSBsZW5ndGhcbipcbiogICBAbWV0aG9kIGlzVHJ5dGVzXG4qICAgQHBhcmFtIHtzdHJpbmd9IHRyeXRlc1xuKiAgIEBwYXJhbSB7aW50ZWdlcn0gbGVuZ3RoIG9wdGlvbmFsXG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc1RyeXRlcyA9IGZ1bmN0aW9uKHRyeXRlcywgbGVuZ3RoKSB7XG5cbiAgICAvLyBJZiBubyBsZW5ndGggc3BlY2lmaWVkLCBqdXN0IHZhbGlkYXRlIHRoZSB0cnl0ZXNcbiAgICBpZiAoIWxlbmd0aCkgbGVuZ3RoID0gXCIwLFwiXG5cbiAgICB2YXIgcmVnZXhUcnl0ZXMgPSBuZXcgUmVnRXhwKFwiXls5QS1aXXtcIiArIGxlbmd0aCArXCJ9JFwiKTtcbiAgICByZXR1cm4gcmVnZXhUcnl0ZXMudGVzdCh0cnl0ZXMpICYmIGlzU3RyaW5nKHRyeXRlcyk7XG59XG5cbi8qKlxuKiAgIGNoZWNrcyBpZiBpbnB1dCBpcyBjb3JyZWN0IHRyeXRlcyBjb25zaXN0aW5nIG9mIEEtWjlcbiogICBvcHRpb25hbGx5IHZhbGlkYXRlIGxlbmd0aFxuKlxuKiAgIEBtZXRob2QgaXNOaW5lc1RyeXRlc1xuKiAgIEBwYXJhbSB7c3RyaW5nfSB0cnl0ZXNcbiogICBAcmV0dXJucyB7Ym9vbGVhbn1cbioqL1xudmFyIGlzTmluZXNUcnl0ZXMgPSBmdW5jdGlvbih0cnl0ZXMpIHtcblxuICAgIHJldHVybiAvXls5XSskLy50ZXN0KHRyeXRlcykgJiYgaXNTdHJpbmcodHJ5dGVzKTtcbn1cblxuLyoqXG4qICAgY2hlY2tzIGlmIGludGVnZXIgdmFsdWVcbipcbiogICBAbWV0aG9kIGlzVmFsdWVcbiogICBAcGFyYW0ge3N0cmluZ30gdmFsdWVcbiogICBAcmV0dXJucyB7Ym9vbGVhbn1cbioqL1xudmFyIGlzVmFsdWUgPSBmdW5jdGlvbih2YWx1ZSkge1xuXG4gICAgLy8gY2hlY2sgaWYgY29ycmVjdCBudW1iZXJcbiAgICByZXR1cm4gTnVtYmVyLmlzSW50ZWdlcih2YWx1ZSlcbn1cblxuLyoqXG4qICAgY2hlY2tzIHdoZXRoZXIgaW5wdXQgaXMgYSB2YWx1ZSBvciBub3QuIENhbiBiZSBhIHN0cmluZywgZmxvYXQgb3IgaW50ZWdlclxuKlxuKiAgIEBtZXRob2QgaXNOdW1cbiogICBAcGFyYW0ge2ludH1cbiogICBAcmV0dXJucyB7Ym9vbGVhbn1cbioqL1xudmFyIGlzTnVtID0gZnVuY3Rpb24oaW5wdXQpIHtcblxuICAgIHJldHVybiAvXihcXGQrXFwuP1xcZHswLDE1fXxcXC5cXGR7MCwxNX0pJC8udGVzdChpbnB1dCk7XG59XG5cbi8qKlxuKiAgIGNoZWNrcyBpZiBpbnB1dCBpcyBjb3JyZWN0IGhhc2hcbipcbiogICBAbWV0aG9kIGlzSGFzaFxuKiAgIEBwYXJhbSB7c3RyaW5nfSBoYXNoXG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc0hhc2ggPSBmdW5jdGlvbihoYXNoKSB7XG5cbiAgICAvLyBDaGVjayBpZiB2YWxpZCwgODEgdHJ5dGVzXG4gICAgaWYgKCFpc1RyeXRlcyhoYXNoLCA4MSkpIHtcblxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG59XG5cbi8qKlxuKiAgIGNoZWNrcyB3aGV0aGVyIGlucHV0IGlzIGEgc3RyaW5nIG9yIG5vdFxuKlxuKiAgIEBtZXRob2QgaXNTdHJpbmdcbiogICBAcGFyYW0ge3N0cmluZ31cbiogICBAcmV0dXJucyB7Ym9vbGVhbn1cbioqL1xudmFyIGlzU3RyaW5nID0gZnVuY3Rpb24oc3RyaW5nKSB7XG5cbiAgICByZXR1cm4gdHlwZW9mIHN0cmluZyA9PT0gJ3N0cmluZyc7XG59XG5cblxuLyoqXG4qICAgY2hlY2tzIHdoZXRoZXIgaW5wdXQgaXMgYW4gYXJyYXkgb3Igbm90XG4qXG4qICAgQG1ldGhvZCBpc0FycmF5XG4qICAgQHBhcmFtIHtvYmplY3R9XG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc0FycmF5ID0gZnVuY3Rpb24oYXJyYXkpIHtcblxuICAgIHJldHVybiBhcnJheSBpbnN0YW5jZW9mIEFycmF5O1xufVxuXG5cbi8qKlxuKiAgIGNoZWNrcyB3aGV0aGVyIGlucHV0IGlzIG9iamVjdCBvciBub3RcbipcbiogICBAbWV0aG9kIGlzT2JqZWN0XG4qICAgQHBhcmFtIHtvYmplY3R9XG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc09iamVjdCA9IGZ1bmN0aW9uKG9iamVjdCkge1xuXG4gICAgcmV0dXJuIHR5cGVvZiBvYmplY3QgPT09ICdvYmplY3QnO1xufVxuXG5cblxuLyoqXG4qICAgY2hlY2tzIGlmIGlucHV0IGlzIGNvcnJlY3QgaGFzaFxuKlxuKiAgIEBtZXRob2QgaXNUcmFuc2ZlcnNBcnJheVxuKiAgIEBwYXJhbSB7YXJyYXl9IGhhc2hcbiogICBAcmV0dXJucyB7Ym9vbGVhbn1cbioqL1xudmFyIGlzVHJhbnNmZXJzQXJyYXkgPSBmdW5jdGlvbih0cmFuc2ZlcnNBcnJheSkge1xuXG4gICAgaWYgKCFpc0FycmF5KHRyYW5zZmVyc0FycmF5KSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0cmFuc2ZlcnNBcnJheS5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIHZhciB0cmFuc2ZlciA9IHRyYW5zZmVyc0FycmF5W2ldO1xuXG4gICAgICAgIC8vIENoZWNrIGlmIHZhbGlkIGFkZHJlc3NcbiAgICAgICAgdmFyIGFkZHJlc3MgPSB0cmFuc2Zlci5hZGRyZXNzO1xuICAgICAgICBpZiAoIWlzQWRkcmVzcyhhZGRyZXNzKSkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gVmFsaWRpdHkgY2hlY2sgZm9yIHZhbHVlXG4gICAgICAgIHZhciB2YWx1ZSA9IHRyYW5zZmVyLnZhbHVlO1xuICAgICAgICBpZiAoIWlzVmFsdWUodmFsdWUpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDaGVjayBpZiBtZXNzYWdlIGlzIGNvcnJlY3QgdHJ5dGVzIG9mIGFueSBsZW5ndGhcbiAgICAgICAgdmFyIG1lc3NhZ2UgPSB0cmFuc2Zlci5tZXNzYWdlO1xuICAgICAgICBpZiAoIWlzVHJ5dGVzKG1lc3NhZ2UsIFwiMCxcIikpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIENoZWNrIGlmIHRhZyBpcyBjb3JyZWN0IHRyeXRlcyBvZiB7MCwyN30gdHJ5dGVzXG4gICAgICAgIHZhciB0YWcgPSB0cmFuc2Zlci50YWcgfHwgdHJhbnNmZXIub2Jzb2xldGVUYWc7XG4gICAgICAgIGlmICghaXNUcnl0ZXModGFnLCBcIjAsMjdcIikpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG59XG5cbi8qKlxuKiAgIGNoZWNrcyBpZiBpbnB1dCBpcyBsaXN0IG9mIGNvcnJlY3QgdHJ5dGVzXG4qXG4qICAgQG1ldGhvZCBpc0FycmF5T2ZIYXNoZXNcbiogICBAcGFyYW0ge2xpc3R9IGhhc2hlc0FycmF5XG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc0FycmF5T2ZIYXNoZXMgPSBmdW5jdGlvbihoYXNoZXNBcnJheSkge1xuXG4gICAgaWYgKCFpc0FycmF5KGhhc2hlc0FycmF5KSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBoYXNoZXNBcnJheS5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIHZhciBoYXNoID0gaGFzaGVzQXJyYXlbaV07XG5cbiAgICAgICAgLy8gQ2hlY2sgaWYgYWRkcmVzcyB3aXRoIGNoZWNrc3VtXG4gICAgICAgIGlmIChoYXNoLmxlbmd0aCA9PT0gOTApIHtcblxuICAgICAgICAgICAgaWYgKCFpc1RyeXRlcyhoYXNoLCA5MCkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgIH0gZWxzZSB7XG5cbiAgICAgICAgICAgIGlmICghaXNUcnl0ZXMoaGFzaCwgODEpKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG59XG5cbi8qKlxuKiAgIGNoZWNrcyBpZiBpbnB1dCBpcyBsaXN0IG9mIGNvcnJlY3QgdHJ5dGVzXG4qXG4qICAgQG1ldGhvZCBpc0FycmF5T2ZUcnl0ZXNcbiogICBAcGFyYW0ge2xpc3R9IHRyeXRlc0FycmF5XG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc0FycmF5T2ZUcnl0ZXMgPSBmdW5jdGlvbih0cnl0ZXNBcnJheSkge1xuXG4gICAgaWYgKCFpc0FycmF5KHRyeXRlc0FycmF5KSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0cnl0ZXNBcnJheS5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIHZhciB0cnl0ZVZhbHVlID0gdHJ5dGVzQXJyYXlbaV07XG5cbiAgICAgICAgLy8gQ2hlY2sgaWYgY29ycmVjdCAyNjczIHRyeXRlc1xuICAgICAgICBpZiAoIWlzVHJ5dGVzKHRyeXRlVmFsdWUsIDI2NzMpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbn1cblxuLyoqXG4qICAgY2hlY2tzIGlmIGF0dGFjaGVkIHRyeXRlcyBpZiBsYXN0IDI0MSB0cnl0ZXMgYXJlIG5vbi16ZXJvXG4qXG4qICAgQG1ldGhvZCBpc0FycmF5T2ZBdHRhY2hlZFRyeXRlc1xuKiAgIEBwYXJhbSB7YXJyYXl9IHRyeXRlc0FycmF5XG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc0FycmF5T2ZBdHRhY2hlZFRyeXRlcyA9IGZ1bmN0aW9uKHRyeXRlc0FycmF5KSB7XG5cbiAgICBpZiAoIWlzQXJyYXkodHJ5dGVzQXJyYXkpKSByZXR1cm4gZmFsc2U7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRyeXRlc0FycmF5Lmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgdmFyIHRyeXRlVmFsdWUgPSB0cnl0ZXNBcnJheVtpXTtcblxuICAgICAgICAvLyBDaGVjayBpZiBjb3JyZWN0IDI2NzMgdHJ5dGVzXG4gICAgICAgIGlmICghaXNUcnl0ZXModHJ5dGVWYWx1ZSwgMjY3MykpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZhciBsYXN0VHJ5dGVzID0gdHJ5dGVWYWx1ZS5zbGljZSgyNjczIC0gKDMgKiA4MSkpO1xuXG4gICAgICAgIGlmICgvXls5XSskLy50ZXN0KGxhc3RUcnl0ZXMpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbn1cblxuLyoqXG4qICAgY2hlY2tzIGlmIGNvcnJlY3QgYnVuZGxlIHdpdGggdHJhbnNhY3Rpb24gb2JqZWN0XG4qXG4qICAgQG1ldGhvZCBpc0FycmF5T2ZUeE9iamVjdHNcbiogICBAcGFyYW0ge2FycmF5fSBidW5kbGVcbiogICBAcmV0dXJucyB7Ym9vbGVhbn1cbioqL1xudmFyIGlzQXJyYXlPZlR4T2JqZWN0cyA9IGZ1bmN0aW9uKGJ1bmRsZSkge1xuXG4gICAgaWYgKCFpc0FycmF5KGJ1bmRsZSkgfHwgYnVuZGxlLmxlbmd0aCA9PT0gMCkgcmV0dXJuIGZhbHNlO1xuXG4gICAgdmFyIHZhbGlkQXJyYXkgPSB0cnVlO1xuXG4gICAgYnVuZGxlLmZvckVhY2goZnVuY3Rpb24odHhPYmplY3QpIHtcblxuICAgICAgICB2YXIga2V5c1RvVmFsaWRhdGUgPSBbXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAga2V5OiAnaGFzaCcsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc0hhc2gsXG4gICAgICAgICAgICAgICAgYXJnczogbnVsbFxuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ3NpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudCcsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1RyeXRlcyxcbiAgICAgICAgICAgICAgICBhcmdzOiAyMTg3XG4gICAgICAgICAgICB9LCB7XG4gICAgICAgICAgICAgICAga2V5OiAnYWRkcmVzcycsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc0hhc2gsXG4gICAgICAgICAgICAgICAgYXJnczogbnVsbFxuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ3ZhbHVlJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzVmFsdWUsXG4gICAgICAgICAgICAgICAgYXJnczogbnVsbFxuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ29ic29sZXRlVGFnJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzVHJ5dGVzLFxuICAgICAgICAgICAgICAgIGFyZ3M6IDI3XG4gICAgICAgICAgICB9LCB7XG4gICAgICAgICAgICAgICAga2V5OiAndGltZXN0YW1wJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzVmFsdWUsXG4gICAgICAgICAgICAgICAgYXJnczogbnVsbFxuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ2N1cnJlbnRJbmRleCcsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1ZhbHVlLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0se1xuICAgICAgICAgICAgICAgIGtleTogJ2xhc3RJbmRleCcsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1ZhbHVlLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICdidW5kbGUnLFxuICAgICAgICAgICAgICAgIHZhbGlkYXRvcjogaXNIYXNoLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICd0cnVua1RyYW5zYWN0aW9uJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzSGFzaCxcbiAgICAgICAgICAgICAgICBhcmdzOiBudWxsXG4gICAgICAgICAgICB9LCB7XG4gICAgICAgICAgICAgICAga2V5OiAnYnJhbmNoVHJhbnNhY3Rpb24nLFxuICAgICAgICAgICAgICAgIHZhbGlkYXRvcjogaXNIYXNoLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICd0YWcnLFxuICAgICAgICAgICAgICAgIHZhbGlkYXRvcjogaXNUcnl0ZXMsXG4gICAgICAgICAgICAgICAgYXJnczogMjdcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICdhdHRhY2htZW50VGltZXN0YW1wJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzVmFsdWUsXG4gICAgICAgICAgICAgICAgYXJnczogbnVsbFxuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ2F0dGFjaG1lbnRUaW1lc3RhbXBMb3dlckJvdW5kJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzVmFsdWUsXG4gICAgICAgICAgICAgICAgYXJnczogbnVsbFxuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ2F0dGFjaG1lbnRUaW1lc3RhbXBVcHBlckJvdW5kJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzVmFsdWUsXG4gICAgICAgICAgICAgICAgYXJnczogbnVsbFxuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ25vbmNlJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzVHJ5dGVzLFxuICAgICAgICAgICAgICAgIGFyZ3M6IDI3XG4gICAgICAgICAgICB9XG4gICAgICAgIF1cblxuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGtleXNUb1ZhbGlkYXRlLmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgICAgIHZhciBrZXkgPSBrZXlzVG9WYWxpZGF0ZVtpXS5rZXk7XG4gICAgICAgICAgICB2YXIgdmFsaWRhdG9yID0ga2V5c1RvVmFsaWRhdGVbaV0udmFsaWRhdG9yO1xuICAgICAgICAgICAgdmFyIGFyZ3MgPSBrZXlzVG9WYWxpZGF0ZVtpXS5hcmdzXG5cbiAgICAgICAgICAgIC8vIElmIGlucHV0IGRvZXMgbm90IGhhdmUga2V5SW5kZXggYW5kIGFkZHJlc3MsIHJldHVybiBmYWxzZVxuICAgICAgICAgICAgaWYgKCF0eE9iamVjdC5oYXNPd25Qcm9wZXJ0eShrZXkpKSB7XG4gICAgICAgICAgICAgICAgdmFsaWRBcnJheSA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBJZiBpbnB1dCB2YWxpZGF0b3IgZnVuY3Rpb24gZG9lcyBub3QgcmV0dXJuIHRydWUsIGV4aXRcbiAgICAgICAgICAgIGlmICghdmFsaWRhdG9yKHR4T2JqZWN0W2tleV0sIGFyZ3MpKSB7XG4gICAgICAgICAgICAgICAgdmFsaWRBcnJheSA9IGZhbHNlO1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfSlcblxuICAgIHJldHVybiB2YWxpZEFycmF5O1xufVxuXG4vKipcbiogICBjaGVja3MgaWYgY29ycmVjdCBpbnB1dHMgbGlzdFxuKlxuKiAgIEBtZXRob2QgaXNJbnB1dHNcbiogICBAcGFyYW0ge2FycmF5fSBpbnB1dHNcbiogICBAcmV0dXJucyB7Ym9vbGVhbn1cbioqL1xudmFyIGlzSW5wdXRzID0gZnVuY3Rpb24oaW5wdXRzKSB7XG5cbiAgICBpZiAoIWlzQXJyYXkoaW5wdXRzKSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBpbnB1dHMubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICB2YXIgaW5wdXQgPSBpbnB1dHNbaV07XG5cbiAgICAgICAgLy8gSWYgaW5wdXQgZG9lcyBub3QgaGF2ZSBrZXlJbmRleCBhbmQgYWRkcmVzcywgcmV0dXJuIGZhbHNlXG4gICAgICAgIGlmICghaW5wdXQuaGFzT3duUHJvcGVydHkoJ3NlY3VyaXR5JykgfHwgIWlucHV0Lmhhc093blByb3BlcnR5KCdrZXlJbmRleCcpIHx8ICFpbnB1dC5oYXNPd25Qcm9wZXJ0eSgnYWRkcmVzcycpKSByZXR1cm4gZmFsc2U7XG5cbiAgICAgICAgaWYgKCFpc0FkZHJlc3MoaW5wdXQuYWRkcmVzcykpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghaXNWYWx1ZShpbnB1dC5zZWN1cml0eSkpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIGlmICghaXNWYWx1ZShpbnB1dC5rZXlJbmRleCkpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xufVxuXG4vKipcbiogICBDaGVja3MgdGhhdCBhIGdpdmVuIHVyaSBpcyB2YWxpZFxuKlxuKiAgIFZhbGlkIEV4YW1wbGVzOlxuKiAgIHVkcDovL1syMDAxOmRiODphMGI6MTJmMDo6MV06MTQyNjVcbiogICB1ZHA6Ly9bMjAwMTpkYjg6YTBiOjEyZjA6OjFdXG4qICAgdWRwOi8vOC44LjguODoxNDI2NVxuKiAgIHVkcDovL2RvbWFpbi5jb21cbiogICB1ZHA6Ly9kb21haW4yLmNvbToxNDI2NVxuKlxuKiAgIEBtZXRob2QgaXNVcmlcbiogICBAcGFyYW0ge3N0cmluZ30gbm9kZVxuKiAgIEByZXR1cm5zIHtib29sfSB2YWxpZFxuKiovXG52YXIgaXNVcmkgPSBmdW5jdGlvbihub2RlKSB7XG5cbiAgICB2YXIgZ2V0SW5zaWRlID0gL14odWRwfHRjcCk6XFwvXFwvKFtcXFtdW15cXF1cXC5dKltcXF1dfFteXFxbXFxdOl0qKVs6XXswLDF9KFswLTldezEsfSR8JCkvaTtcblxuICAgIHZhciBzdHJpcEJyYWNrZXRzID0gL1tcXFtdezAsMX0oW15cXFtcXF1dKilbXFxdXXswLDF9LztcblxuICAgIHZhciB1cmlUZXN0ID0gLygoXlxccyooKChbMC05XXxbMS05XVswLTldfDFbMC05XXsyfXwyWzAtNF1bMC05XXwyNVswLTVdKVxcLil7M30oWzAtOV18WzEtOV1bMC05XXwxWzAtOV17Mn18MlswLTRdWzAtOV18MjVbMC01XSkpXFxzKiQpfCheXFxzKigoKFswLTlBLUZhLWZdezEsNH06KXs3fShbMC05QS1GYS1mXXsxLDR9fDopKXwoKFswLTlBLUZhLWZdezEsNH06KXs2fSg6WzAtOUEtRmEtZl17MSw0fXwoKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKShcXC4oMjVbMC01XXwyWzAtNF1cXGR8MVxcZFxcZHxbMS05XT9cXGQpKXszfSl8OikpfCgoWzAtOUEtRmEtZl17MSw0fTopezV9KCgoOlswLTlBLUZhLWZdezEsNH0pezEsMn0pfDooKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKShcXC4oMjVbMC01XXwyWzAtNF1cXGR8MVxcZFxcZHxbMS05XT9cXGQpKXszfSl8OikpfCgoWzAtOUEtRmEtZl17MSw0fTopezR9KCgoOlswLTlBLUZhLWZdezEsNH0pezEsM30pfCgoOlswLTlBLUZhLWZdezEsNH0pPzooKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKShcXC4oMjVbMC01XXwyWzAtNF1cXGR8MVxcZFxcZHxbMS05XT9cXGQpKXszfSkpfDopKXwoKFswLTlBLUZhLWZdezEsNH06KXszfSgoKDpbMC05QS1GYS1mXXsxLDR9KXsxLDR9KXwoKDpbMC05QS1GYS1mXXsxLDR9KXswLDJ9OigoMjVbMC01XXwyWzAtNF1cXGR8MVxcZFxcZHxbMS05XT9cXGQpKFxcLigyNVswLTVdfDJbMC00XVxcZHwxXFxkXFxkfFsxLTldP1xcZCkpezN9KSl8OikpfCgoWzAtOUEtRmEtZl17MSw0fTopezJ9KCgoOlswLTlBLUZhLWZdezEsNH0pezEsNX0pfCgoOlswLTlBLUZhLWZdezEsNH0pezAsM306KCgyNVswLTVdfDJbMC00XVxcZHwxXFxkXFxkfFsxLTldP1xcZCkoXFwuKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKSl7M30pKXw6KSl8KChbMC05QS1GYS1mXXsxLDR9Oil7MX0oKCg6WzAtOUEtRmEtZl17MSw0fSl7MSw2fSl8KCg6WzAtOUEtRmEtZl17MSw0fSl7MCw0fTooKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKShcXC4oMjVbMC01XXwyWzAtNF1cXGR8MVxcZFxcZHxbMS05XT9cXGQpKXszfSkpfDopKXwoOigoKDpbMC05QS1GYS1mXXsxLDR9KXsxLDd9KXwoKDpbMC05QS1GYS1mXXsxLDR9KXswLDV9OigoMjVbMC01XXwyWzAtNF1cXGR8MVxcZFxcZHxbMS05XT9cXGQpKFxcLigyNVswLTVdfDJbMC00XVxcZHwxXFxkXFxkfFsxLTldP1xcZCkpezN9KSl8OikpKSglLispP1xccyokKSl8KF5cXHMqKCg/PS57MSwyNTV9JCkoPz0uKltBLVphLXpdLiopWzAtOUEtWmEtel0oPzooPzpbMC05QS1aYS16XXxcXGItKXswLDYxfVswLTlBLVphLXpdKT8oPzpcXC5bMC05QS1aYS16XSg/Oig/OlswLTlBLVphLXpdfFxcYi0pezAsNjF9WzAtOUEtWmEtel0pPykqKVxccyokKS87XG5cbiAgICBpZighZ2V0SW5zaWRlLnRlc3Qobm9kZSkpIHtcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIHJldHVybiB1cmlUZXN0LnRlc3Qoc3RyaXBCcmFja2V0cy5leGVjKGdldEluc2lkZS5leGVjKG5vZGUpWzFdKVsxXSk7XG59XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICAgIGlzQWRkcmVzczogaXNBZGRyZXNzLFxuICAgIGlzVHJ5dGVzOiBpc1RyeXRlcyxcbiAgICBpc05pbmVzVHJ5dGVzOiBpc05pbmVzVHJ5dGVzLFxuICAgIGlzVmFsdWU6IGlzVmFsdWUsXG4gICAgaXNIYXNoOiBpc0hhc2gsXG4gICAgaXNUcmFuc2ZlcnNBcnJheTogaXNUcmFuc2ZlcnNBcnJheSxcbiAgICBpc0FycmF5T2ZIYXNoZXM6IGlzQXJyYXlPZkhhc2hlcyxcbiAgICBpc0FycmF5T2ZUcnl0ZXM6IGlzQXJyYXlPZlRyeXRlcyxcbiAgICBpc0FycmF5T2ZBdHRhY2hlZFRyeXRlczogaXNBcnJheU9mQXR0YWNoZWRUcnl0ZXMsXG4gICAgaXNBcnJheU9mVHhPYmplY3RzOiBpc0FycmF5T2ZUeE9iamVjdHMsXG4gICAgaXNJbnB1dHM6IGlzSW5wdXRzLFxuICAgIGlzU3RyaW5nOiBpc1N0cmluZyxcbiAgICBpc051bTogaXNOdW0sXG4gICAgaXNBcnJheTogaXNBcnJheSxcbiAgICBpc09iamVjdDogaXNPYmplY3QsXG4gICAgaXNVcmk6IGlzVXJpXG59XG4iLCJ2YXIgaW5wdXRWYWxpZGF0b3IgID0gICByZXF1aXJlKFwiLi9pbnB1dFZhbGlkYXRvclwiKTtcbnZhciBDdXJsICAgICAgICAgICAgPSAgIHJlcXVpcmUoXCIuLi9jcnlwdG8vY3VybC9jdXJsXCIpO1xudmFyIEtlcmwgICAgICAgICAgICA9ICAgcmVxdWlyZShcIi4uL2NyeXB0by9rZXJsL2tlcmxcIik7XG52YXIgQ29udmVydGVyICAgICAgID0gICByZXF1aXJlKFwiLi4vY3J5cHRvL2NvbnZlcnRlci9jb252ZXJ0ZXJcIik7XG52YXIgU2lnbmluZyAgICAgICAgID0gICByZXF1aXJlKFwiLi4vY3J5cHRvL3NpZ25pbmcvc2lnbmluZ1wiKTtcbnZhciBDcnlwdG9KUyAgICAgICAgPSAgIHJlcXVpcmUoXCJjcnlwdG8tanNcIik7XG52YXIgYXNjaWkgICAgICAgICAgID0gICByZXF1aXJlKFwiLi9hc2NpaVRvVHJ5dGVzXCIpO1xudmFyIGV4dHJhY3RKc29uICAgICA9ICAgcmVxdWlyZShcIi4vZXh0cmFjdEpzb25cIik7XG5cblxuLyoqXG4qICAgVGFibGUgb2YgSU9UQSBVbml0cyBiYXNlZCBvZmYgb2YgdGhlIHN0YW5kYXJkIFN5c3RlbSBvZiBVbml0c1xuKiovXG52YXIgdW5pdE1hcCA9IHtcbiAgICAnaScgICA6ICAgMSxcbiAgICAnS2knICA6ICAgMTAwMCxcbiAgICAnTWknICA6ICAgMTAwMDAwMCxcbiAgICAnR2knICA6ICAgMTAwMDAwMDAwMCxcbiAgICAnVGknICA6ICAgMTAwMDAwMDAwMDAwMCxcbiAgICAnUGknICA6ICAgMTAwMDAwMDAwMDAwMDAwMCAgLy8gRm9yIHRoZSB2ZXJ5LCB2ZXJ5IHJpY2hcbn1cblxuLyoqXG4qICAgY29udmVydHMgSU9UQSB1bml0c1xuKlxuKiAgIEBtZXRob2QgY29udmVydFVuaXRzXG4qICAgQHBhcmFtIHtzdHJpbmcgfHwgaW50IHx8IGZsb2F0fSB2YWx1ZVxuKiAgIEBwYXJhbSB7c3RyaW5nfSBmcm9tVW5pdFxuKiAgIEBwYXJhbSB7c3RyaW5nfSB0b1VuaXRcbiogICBAcmV0dXJucyB7aW50ZWdlcn0gY29udmVydGVkXG4qKi9cbnZhciBjb252ZXJ0VW5pdHMgPSBmdW5jdGlvbih2YWx1ZSwgZnJvbVVuaXQsIHRvVW5pdCkge1xuXG4gICAgLy8gQ2hlY2sgaWYgd3JvbmcgdW5pdCBwcm92aWRlZFxuICAgIGlmICh1bml0TWFwW2Zyb21Vbml0XSA9PT0gdW5kZWZpbmVkIHx8IHVuaXRNYXBbdG9Vbml0XSA9PT0gdW5kZWZpbmVkKSB7XG5cbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiSW52YWxpZCB1bml0IHByb3ZpZGVkXCIpO1xuICAgIH1cblxuICAgIHZhciBhZnRlckNvbW1hID0gU3RyaW5nKHZhbHVlKS5tYXRjaCgvXFwuKFtcXGRdKykkLyk7XG5cbiAgICBpZiAoYWZ0ZXJDb21tYSAmJiBhZnRlckNvbW1hWzFdLmxlbmd0aCA+IFN0cmluZyh1bml0TWFwW2Zyb21Vbml0XSkubGVuZ3RoIC0gMSkge1xuXG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcIlRvbyBtYW55IGRpZ2l0cyBhZnRlciBjb21tYVwiKTtcbiAgICB9XG5cbiAgICAvLyBJZiBub3QgdmFsaWQgdmFsdWUsIHRocm93IGVycm9yXG4gICAgaWYgKCFpbnB1dFZhbGlkYXRvci5pc051bSh2YWx1ZSkpIHtcblxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJJbnZhbGlkIHZhbHVlXCIpO1xuICAgIH1cblxuXG4gICAgdmFyIGZsb2F0VmFsdWUgPSBwYXJzZUZsb2F0KHZhbHVlKTtcblxuICAgIHZhciBjb252ZXJ0ZWQgPSAoZmxvYXRWYWx1ZSAqIHVuaXRNYXBbZnJvbVVuaXRdKSAvIHVuaXRNYXBbdG9Vbml0XTtcblxuICAgIHJldHVybiBjb252ZXJ0ZWQ7XG59XG5cbi8qKlxuKiAgIEdlbmVyYXRlcyB0aGUgOS10cnl0ZSBjaGVja3N1bSBvZiBhbiBhZGRyZXNzXG4qXG4qICAgQG1ldGhvZCBhZGRDaGVja3N1bVxuKiAgIEBwYXJhbSB7c3RyaW5nIHwgbGlzdH0gaW5wdXRWYWx1ZVxuKiAgIEBwYXJhbSB7aW50fSBjaGVja3N1bUxlbmd0aFxuQCAgIEBwYXJhbSB7Ym9vbH0gaXNBZGRyZXNzIGRlZmF1bHQgaXMgdHJ1ZVxuKiAgIEByZXR1cm5zIHtzdHJpbmcgfCBsaXN0fSBhZGRyZXNzICh3aXRoIGNoZWNrc3VtKVxuKiovXG52YXIgYWRkQ2hlY2tzdW0gPSBmdW5jdGlvbihpbnB1dFZhbHVlLCBjaGVja3N1bUxlbmd0aCwgaXNBZGRyZXNzKSB7XG5cbiAgICAvLyBjaGVja3N1bSBsZW5ndGggaXMgZWl0aGVyIHVzZXIgZGVmaW5lZCwgb3IgOSB0cnl0ZXNcbiAgICB2YXIgY2hlY2tzdW1MZW5ndGggPSBjaGVja3N1bUxlbmd0aCB8fCA5O1xuICAgIHZhciBpc0FkZHJlc3MgPSAoaXNBZGRyZXNzICE9PSBmYWxzZSk7XG5cbiAgICAvLyB0aGUgbGVuZ3RoIG9mIHRoZSB0cnl0ZXMgdG8gYmUgdmFsaWRhdGVkXG4gICAgdmFyIHZhbGlkYXRpb25MZW5ndGggPSBpc0FkZHJlc3MgPyA4MSA6IG51bGw7XG5cbiAgICB2YXIgaXNTaW5nbGVJbnB1dCA9IGlucHV0VmFsaWRhdG9yLmlzU3RyaW5nKCBpbnB1dFZhbHVlICk7XG5cbiAgICAvLyBJZiBvbmx5IHNpbmdsZSBhZGRyZXNzLCB0dXJuIGl0IGludG8gYW4gYXJyYXlcbiAgICBpZiAoIGlzU2luZ2xlSW5wdXQgKSBpbnB1dFZhbHVlID0gbmV3IEFycmF5KCBpbnB1dFZhbHVlICk7XG5cbiAgICB2YXIgaW5wdXRzV2l0aENoZWNrc3VtID0gW107XG5cbiAgICBpbnB1dFZhbHVlLmZvckVhY2goZnVuY3Rpb24odGhpc1ZhbHVlKSB7XG5cbiAgICAgICAgLy8gY2hlY2sgaWYgY29ycmVjdCB0cnl0ZXNcbiAgICAgICAgaWYgKCFpbnB1dFZhbGlkYXRvci5pc1RyeXRlcyh0aGlzVmFsdWUsIHZhbGlkYXRpb25MZW5ndGgpKSB7XG4gICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJJbnZhbGlkIGlucHV0XCIpO1xuICAgICAgICB9XG5cbiAgICAgICAgdmFyIGtlcmwgPSBuZXcgS2VybCgpO1xuICAgICAgICBrZXJsLmluaXRpYWxpemUoKTtcblxuICAgICAgICAvLyBBZGRyZXNzIHRyaXRzXG4gICAgICAgIHZhciBhZGRyZXNzVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModGhpc1ZhbHVlKTtcblxuICAgICAgICAvLyBDaGVja3N1bSB0cml0c1xuICAgICAgICB2YXIgY2hlY2tzdW1Ucml0cyA9IFtdO1xuXG4gICAgICAgIC8vIEFic29yYiBhZGRyZXNzIHRyaXRzXG4gICAgICAgIGtlcmwuYWJzb3JiKGFkZHJlc3NUcml0cywgMCwgYWRkcmVzc1RyaXRzLmxlbmd0aCk7XG5cbiAgICAgICAgLy8gU3F1ZWV6ZSBjaGVja3N1bSB0cml0c1xuICAgICAgICBrZXJsLnNxdWVlemUoY2hlY2tzdW1Ucml0cywgMCwgQ3VybC5IQVNIX0xFTkdUSCk7XG5cbiAgICAgICAgLy8gRmlyc3QgOSB0cnl0ZXMgYXMgY2hlY2tzdW1cbiAgICAgICAgdmFyIGNoZWNrc3VtID0gQ29udmVydGVyLnRyeXRlcyggY2hlY2tzdW1Ucml0cyApLnN1YnN0cmluZyggODEgLSBjaGVja3N1bUxlbmd0aCwgODEgKTtcbiAgICAgICAgaW5wdXRzV2l0aENoZWNrc3VtLnB1c2goIHRoaXNWYWx1ZSArIGNoZWNrc3VtICk7XG4gICAgfSk7XG5cbiAgICBpZiAoaXNTaW5nbGVJbnB1dCkge1xuXG4gICAgICAgIHJldHVybiBpbnB1dHNXaXRoQ2hlY2tzdW1bIDAgXTtcblxuICAgIH0gZWxzZSB7XG5cbiAgICAgICAgcmV0dXJuIGlucHV0c1dpdGhDaGVja3N1bTtcblxuICAgIH1cbn1cblxuLyoqXG4qICAgUmVtb3ZlcyB0aGUgOS10cnl0ZSBjaGVja3N1bSBvZiBhbiBhZGRyZXNzXG4qXG4qICAgQG1ldGhvZCBub0NoZWNrc3VtXG4qICAgQHBhcmFtIHtzdHJpbmcgfCBsaXN0fSBhZGRyZXNzXG4qICAgQHJldHVybnMge3N0cmluZyB8IGxpc3R9IGFkZHJlc3MgKHdpdGhvdXQgY2hlY2tzdW0pXG4qKi9cbnZhciBub0NoZWNrc3VtID0gZnVuY3Rpb24oYWRkcmVzcykge1xuXG4gICAgdmFyIGlzU2luZ2xlQWRkcmVzcyA9IGlucHV0VmFsaWRhdG9yLmlzU3RyaW5nKGFkZHJlc3MpXG5cbiAgICAvLyBJZiBvbmx5IHNpbmdsZSBhZGRyZXNzLCB0dXJuIGl0IGludG8gYW4gYXJyYXlcbiAgICBpZiAoaXNTaW5nbGVBZGRyZXNzKSBhZGRyZXNzID0gbmV3IEFycmF5KGFkZHJlc3MpO1xuXG4gICAgdmFyIGFkZHJlc3Nlc1dpdGhDaGVja3N1bSA9IFtdO1xuXG4gICAgYWRkcmVzcy5mb3JFYWNoKGZ1bmN0aW9uKHRoaXNBZGRyZXNzKSB7XG4gICAgICAgIGFkZHJlc3Nlc1dpdGhDaGVja3N1bS5wdXNoKHRoaXNBZGRyZXNzLnNsaWNlKDAsIDgxKSlcbiAgICB9KVxuXG4gICAgLy8gcmV0dXJuIGVpdGhlciBzdHJpbmcgb3IgdGhlIGxpc3RcbiAgICBpZiAoaXNTaW5nbGVBZGRyZXNzKSB7XG5cbiAgICAgICAgcmV0dXJuIGFkZHJlc3Nlc1dpdGhDaGVja3N1bVswXTtcblxuICAgIH0gZWxzZSB7XG5cbiAgICAgICAgcmV0dXJuIGFkZHJlc3Nlc1dpdGhDaGVja3N1bTtcblxuICAgIH1cbn1cblxuLyoqXG4qICAgVmFsaWRhdGVzIHRoZSBjaGVja3N1bSBvZiBhbiBhZGRyZXNzXG4qXG4qICAgQG1ldGhvZCBpc1ZhbGlkQ2hlY2tzdW1cbiogICBAcGFyYW0ge3N0cmluZ30gYWRkcmVzc1dpdGhDaGVja3N1bVxuKiAgIEByZXR1cm5zIHtib29sfVxuKiovXG52YXIgaXNWYWxpZENoZWNrc3VtID0gZnVuY3Rpb24oYWRkcmVzc1dpdGhDaGVja3N1bSkge1xuXG4gICAgdmFyIGFkZHJlc3NXaXRob3V0Q2hlY2tzdW0gPSBub0NoZWNrc3VtKGFkZHJlc3NXaXRoQ2hlY2tzdW0pO1xuXG4gICAgdmFyIG5ld0NoZWNrc3VtID0gYWRkQ2hlY2tzdW0oYWRkcmVzc1dpdGhvdXRDaGVja3N1bSk7XG5cbiAgICByZXR1cm4gbmV3Q2hlY2tzdW0gPT09IGFkZHJlc3NXaXRoQ2hlY2tzdW07XG59XG5cbi8qKlxuKiAgIENvbnZlcnRzIHRyYW5zYWN0aW9uIHRyeXRlcyBvZiAyNjczIHRyeXRlcyBpbnRvIGEgdHJhbnNhY3Rpb24gb2JqZWN0XG4qXG4qICAgQG1ldGhvZCB0cmFuc2FjdGlvbk9iamVjdFxuKiAgIEBwYXJhbSB7c3RyaW5nfSB0cnl0ZXNcbiogICBAcmV0dXJucyB7U3RyaW5nfSB0cmFuc2FjdGlvbk9iamVjdFxuKiovXG52YXIgdHJhbnNhY3Rpb25PYmplY3QgPSBmdW5jdGlvbih0cnl0ZXMpIHtcblxuICAgIGlmICghdHJ5dGVzKSByZXR1cm47XG5cbiAgICAvLyB2YWxpZGl0eSBjaGVja1xuICAgIGZvciAodmFyIGkgPSAyMjc5OyBpIDwgMjI5NTsgaSsrKSB7XG5cbiAgICAgICAgaWYgKHRyeXRlcy5jaGFyQXQoaSkgIT09IFwiOVwiKSB7XG5cbiAgICAgICAgICAgIHJldHVybiBudWxsO1xuXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICB2YXIgdGhpc1RyYW5zYWN0aW9uID0ge307XG4gICAgdmFyIHRyYW5zYWN0aW9uVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModHJ5dGVzKTtcbiAgICB2YXIgaGFzaCA9IFtdO1xuXG4gICAgdmFyIGN1cmwgPSBuZXcgQ3VybCgpO1xuXG4gICAgLy8gZ2VuZXJhdGUgdGhlIGNvcnJlY3QgdHJhbnNhY3Rpb24gaGFzaFxuICAgIGN1cmwuaW5pdGlhbGl6ZSgpO1xuICAgIGN1cmwuYWJzb3JiKHRyYW5zYWN0aW9uVHJpdHMsIDAsIHRyYW5zYWN0aW9uVHJpdHMubGVuZ3RoKTtcbiAgICBjdXJsLnNxdWVlemUoaGFzaCwgMCwgMjQzKTtcblxuICAgIHRoaXNUcmFuc2FjdGlvbi5oYXNoID0gQ29udmVydGVyLnRyeXRlcyhoYXNoKTtcbiAgICB0aGlzVHJhbnNhY3Rpb24uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50ID0gdHJ5dGVzLnNsaWNlKDAsIDIxODcpO1xuICAgIHRoaXNUcmFuc2FjdGlvbi5hZGRyZXNzID0gdHJ5dGVzLnNsaWNlKDIxODcsIDIyNjgpO1xuICAgIHRoaXNUcmFuc2FjdGlvbi52YWx1ZSA9IENvbnZlcnRlci52YWx1ZSh0cmFuc2FjdGlvblRyaXRzLnNsaWNlKDY4MDQsIDY4MzcpKTtcbiAgICB0aGlzVHJhbnNhY3Rpb24ub2Jzb2xldGVUYWcgPSB0cnl0ZXMuc2xpY2UoMjI5NSwgMjMyMik7XG4gICAgdGhpc1RyYW5zYWN0aW9uLnRpbWVzdGFtcCA9IENvbnZlcnRlci52YWx1ZSh0cmFuc2FjdGlvblRyaXRzLnNsaWNlKDY5NjYsIDY5OTMpKTtcbiAgICB0aGlzVHJhbnNhY3Rpb24uY3VycmVudEluZGV4ID0gQ29udmVydGVyLnZhbHVlKHRyYW5zYWN0aW9uVHJpdHMuc2xpY2UoNjk5MywgNzAyMCkpO1xuICAgIHRoaXNUcmFuc2FjdGlvbi5sYXN0SW5kZXggPSBDb252ZXJ0ZXIudmFsdWUodHJhbnNhY3Rpb25Ucml0cy5zbGljZSg3MDIwLCA3MDQ3KSk7XG4gICAgdGhpc1RyYW5zYWN0aW9uLmJ1bmRsZSA9IHRyeXRlcy5zbGljZSgyMzQ5LCAyNDMwKTtcbiAgICB0aGlzVHJhbnNhY3Rpb24udHJ1bmtUcmFuc2FjdGlvbiA9IHRyeXRlcy5zbGljZSgyNDMwLCAyNTExKTtcbiAgICB0aGlzVHJhbnNhY3Rpb24uYnJhbmNoVHJhbnNhY3Rpb24gPSB0cnl0ZXMuc2xpY2UoMjUxMSwgMjU5Mik7XG5cbiAgICB0aGlzVHJhbnNhY3Rpb24udGFnID0gdHJ5dGVzLnNsaWNlKDI1OTIsIDI2MTkpO1xuICAgIHRoaXNUcmFuc2FjdGlvbi5hdHRhY2htZW50VGltZXN0YW1wID0gQ29udmVydGVyLnZhbHVlKHRyYW5zYWN0aW9uVHJpdHMuc2xpY2UoNzg1NywgNzg4NCkpO1xuICAgIHRoaXNUcmFuc2FjdGlvbi5hdHRhY2htZW50VGltZXN0YW1wTG93ZXJCb3VuZCA9IENvbnZlcnRlci52YWx1ZSh0cmFuc2FjdGlvblRyaXRzLnNsaWNlKDc4ODQsIDc5MTEpKTtcbiAgICB0aGlzVHJhbnNhY3Rpb24uYXR0YWNobWVudFRpbWVzdGFtcFVwcGVyQm91bmQgPSBDb252ZXJ0ZXIudmFsdWUodHJhbnNhY3Rpb25Ucml0cy5zbGljZSg3OTExLCA3OTM4KSk7XG4gICAgdGhpc1RyYW5zYWN0aW9uLm5vbmNlID0gdHJ5dGVzLnNsaWNlKDI2NDYsIDI2NzMpO1xuXG4gICAgcmV0dXJuIHRoaXNUcmFuc2FjdGlvbjtcbn1cblxuLyoqXG4qICAgQ29udmVydHMgYSB0cmFuc2FjdGlvbiBvYmplY3QgaW50byB0cnl0ZXNcbipcbiogICBAbWV0aG9kIHRyYW5zYWN0aW9uVHJ5dGVzXG4qICAgQHBhcmFtIHtvYmplY3R9IHRyYW5zYWN0aW9uVHJ5dGVzXG4qICAgQHJldHVybnMge1N0cmluZ30gdHJ5dGVzXG4qKi9cbnZhciB0cmFuc2FjdGlvblRyeXRlcyA9IGZ1bmN0aW9uKHRyYW5zYWN0aW9uKSB7XG5cbiAgICB2YXIgdmFsdWVUcml0cyA9IENvbnZlcnRlci50cml0cyh0cmFuc2FjdGlvbi52YWx1ZSk7XG4gICAgd2hpbGUgKHZhbHVlVHJpdHMubGVuZ3RoIDwgODEpIHtcbiAgICAgICAgdmFsdWVUcml0c1t2YWx1ZVRyaXRzLmxlbmd0aF0gPSAwO1xuICAgIH1cblxuICAgIHZhciB0aW1lc3RhbXBUcml0cyA9IENvbnZlcnRlci50cml0cyh0cmFuc2FjdGlvbi50aW1lc3RhbXApO1xuICAgIHdoaWxlICh0aW1lc3RhbXBUcml0cy5sZW5ndGggPCAyNykge1xuICAgICAgICB0aW1lc3RhbXBUcml0c1t0aW1lc3RhbXBUcml0cy5sZW5ndGhdID0gMDtcbiAgICB9XG5cbiAgICB2YXIgY3VycmVudEluZGV4VHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModHJhbnNhY3Rpb24uY3VycmVudEluZGV4KTtcbiAgICB3aGlsZSAoY3VycmVudEluZGV4VHJpdHMubGVuZ3RoIDwgMjcpIHtcbiAgICAgICAgY3VycmVudEluZGV4VHJpdHNbY3VycmVudEluZGV4VHJpdHMubGVuZ3RoXSA9IDA7XG4gICAgfVxuXG4gICAgdmFyIGxhc3RJbmRleFRyaXRzID0gQ29udmVydGVyLnRyaXRzKHRyYW5zYWN0aW9uLmxhc3RJbmRleCk7XG4gICAgd2hpbGUgKGxhc3RJbmRleFRyaXRzLmxlbmd0aCA8IDI3KSB7XG4gICAgICAgIGxhc3RJbmRleFRyaXRzW2xhc3RJbmRleFRyaXRzLmxlbmd0aF0gPSAwO1xuICAgIH1cblxuICAgIHZhciBhdHRhY2htZW50VGltZXN0YW1wVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModHJhbnNhY3Rpb24uYXR0YWNobWVudFRpbWVzdGFtcCB8fCAwKTtcbiAgICB3aGlsZSAoYXR0YWNobWVudFRpbWVzdGFtcFRyaXRzLmxlbmd0aCA8IDI3KSB7XG4gICAgICAgIGF0dGFjaG1lbnRUaW1lc3RhbXBUcml0c1thdHRhY2htZW50VGltZXN0YW1wVHJpdHMubGVuZ3RoXSA9IDA7XG4gICAgfVxuXG4gICAgdmFyIGF0dGFjaG1lbnRUaW1lc3RhbXBMb3dlckJvdW5kVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModHJhbnNhY3Rpb24uYXR0YWNobWVudFRpbWVzdGFtcExvd2VyQm91bmQgfHwgMCk7XG4gICAgd2hpbGUgKGF0dGFjaG1lbnRUaW1lc3RhbXBMb3dlckJvdW5kVHJpdHMubGVuZ3RoIDwgMjcpIHtcbiAgICAgICAgYXR0YWNobWVudFRpbWVzdGFtcExvd2VyQm91bmRUcml0c1thdHRhY2htZW50VGltZXN0YW1wTG93ZXJCb3VuZFRyaXRzLmxlbmd0aF0gPSAwO1xuICAgIH1cblxuICAgIHZhciBhdHRhY2htZW50VGltZXN0YW1wVXBwZXJCb3VuZFRyaXRzID0gQ29udmVydGVyLnRyaXRzKHRyYW5zYWN0aW9uLmF0dGFjaG1lbnRUaW1lc3RhbXBVcHBlckJvdW5kIHx8IDApO1xuICAgIHdoaWxlIChhdHRhY2htZW50VGltZXN0YW1wVXBwZXJCb3VuZFRyaXRzLmxlbmd0aCA8IDI3KSB7XG4gICAgICAgIGF0dGFjaG1lbnRUaW1lc3RhbXBVcHBlckJvdW5kVHJpdHNbYXR0YWNobWVudFRpbWVzdGFtcFVwcGVyQm91bmRUcml0cy5sZW5ndGhdID0gMDtcbiAgICB9XG5cbiAgICB0cmFuc2FjdGlvbi50YWcgPSB0cmFuc2FjdGlvbi50YWcgfHwgdHJhbnNhY3Rpb24ub2Jzb2xldGVUYWc7XG5cbiAgICByZXR1cm4gdHJhbnNhY3Rpb24uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50XG4gICAgKyB0cmFuc2FjdGlvbi5hZGRyZXNzXG4gICAgKyBDb252ZXJ0ZXIudHJ5dGVzKHZhbHVlVHJpdHMpXG4gICAgKyB0cmFuc2FjdGlvbi5vYnNvbGV0ZVRhZ1xuICAgICsgQ29udmVydGVyLnRyeXRlcyh0aW1lc3RhbXBUcml0cylcbiAgICArIENvbnZlcnRlci50cnl0ZXMoY3VycmVudEluZGV4VHJpdHMpXG4gICAgKyBDb252ZXJ0ZXIudHJ5dGVzKGxhc3RJbmRleFRyaXRzKVxuICAgICsgdHJhbnNhY3Rpb24uYnVuZGxlXG4gICAgKyB0cmFuc2FjdGlvbi50cnVua1RyYW5zYWN0aW9uXG4gICAgKyB0cmFuc2FjdGlvbi5icmFuY2hUcmFuc2FjdGlvblxuICAgICsgdHJhbnNhY3Rpb24udGFnXG4gICAgKyBDb252ZXJ0ZXIudHJ5dGVzKGF0dGFjaG1lbnRUaW1lc3RhbXBUcml0cylcbiAgICArIENvbnZlcnRlci50cnl0ZXMoYXR0YWNobWVudFRpbWVzdGFtcExvd2VyQm91bmRUcml0cylcbiAgICArIENvbnZlcnRlci50cnl0ZXMoYXR0YWNobWVudFRpbWVzdGFtcFVwcGVyQm91bmRUcml0cylcbiAgICArIHRyYW5zYWN0aW9uLm5vbmNlO1xufVxuXG4vKipcbiogICBDYXRlZ29yaXplcyBhIGxpc3Qgb2YgdHJhbnNmZXJzIGJldHdlZW4gc2VudCBhbmQgcmVjZWl2ZWRcbipcbiogICBAbWV0aG9kIGNhdGVnb3JpemVUcmFuc2ZlcnNcbiogICBAcGFyYW0ge29iamVjdH0gdHJhbnNmZXJzIFRyYW5zZmVycyAoYnVuZGxlcylcbiogICBAcGFyYW0ge2xpc3R9IGFkZHJlc3NlcyBMaXN0IG9mIGFkZHJlc3NlcyB0aGF0IGJlbG9uZyB0byB0aGUgdXNlclxuKiAgIEByZXR1cm5zIHtTdHJpbmd9IHRyeXRlc1xuKiovXG52YXIgY2F0ZWdvcml6ZVRyYW5zZmVycyA9IGZ1bmN0aW9uKHRyYW5zZmVycywgYWRkcmVzc2VzKSB7XG5cbiAgICB2YXIgY2F0ZWdvcml6ZWQgPSB7XG4gICAgICAgICdzZW50JyAgICAgIDogW10sXG4gICAgICAgICdyZWNlaXZlZCcgIDogW11cbiAgICB9XG5cbiAgICAvLyBJdGVyYXRlIG92ZXIgYWxsIGJ1bmRsZXMgYW5kIHNvcnQgdGhlbSBiZXR3ZWVuIGluY29taW5nIGFuZCBvdXRnb2luZyB0cmFuc2ZlcnNcbiAgICB0cmFuc2ZlcnMuZm9yRWFjaChmdW5jdGlvbihidW5kbGUpIHtcblxuICAgICAgICB2YXIgc3BlbnRBbHJlYWR5QWRkZWQgPSBmYWxzZTtcblxuICAgICAgICAvLyBJdGVyYXRlIG92ZXIgZXZlcnkgYnVuZGxlIGVudHJ5XG4gICAgICAgIGJ1bmRsZS5mb3JFYWNoKGZ1bmN0aW9uKGJ1bmRsZUVudHJ5LCBidW5kbGVJbmRleCkge1xuXG4gICAgICAgICAgICAvLyBJZiBidW5kbGUgYWRkcmVzcyBpbiB0aGUgbGlzdCBvZiBhZGRyZXNzZXMgYXNzb2NpYXRlZCB3aXRoIHRoZSBzZWVkXG4gICAgICAgICAgICAvLyBhZGQgdGhlIGJ1bmRsZSB0byB0aGVcbiAgICAgICAgICAgIGlmIChhZGRyZXNzZXMuaW5kZXhPZihidW5kbGVFbnRyeS5hZGRyZXNzKSA+IC0xKSB7XG5cbiAgICAgICAgICAgICAgICAvLyBDaGVjayBpZiBpdCdzIGEgcmVtYWluZGVyIGFkZHJlc3NcbiAgICAgICAgICAgICAgICB2YXIgaXNSZW1haW5kZXIgPSAoYnVuZGxlRW50cnkuY3VycmVudEluZGV4ID09PSBidW5kbGVFbnRyeS5sYXN0SW5kZXgpICYmIGJ1bmRsZUVudHJ5Lmxhc3RJbmRleCAhPT0gMDtcblxuICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIHNlbnQgdHJhbnNhY3Rpb25cbiAgICAgICAgICAgICAgICBpZiAoYnVuZGxlRW50cnkudmFsdWUgPCAwICYmICFzcGVudEFscmVhZHlBZGRlZCAmJiAhaXNSZW1haW5kZXIpIHtcblxuICAgICAgICAgICAgICAgICAgICBjYXRlZ29yaXplZC5zZW50LnB1c2goYnVuZGxlKTtcblxuICAgICAgICAgICAgICAgICAgICAvLyB0b28gbWFrZSBzdXJlIHdlIGRvIG5vdCBhZGQgdHJhbnNhY3Rpb25zIHR3aWNlXG4gICAgICAgICAgICAgICAgICAgIHNwZW50QWxyZWFkeUFkZGVkID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgLy8gY2hlY2sgaWYgcmVjZWl2ZWQgdHJhbnNhY3Rpb24sIG9yIDAgdmFsdWUgKG1lc3NhZ2UpXG4gICAgICAgICAgICAgICAgLy8gYWxzbyBtYWtlIHN1cmUgdGhhdCB0aGlzIGlzIG5vdCBhIDJuZCB0eCBmb3Igc3BlbnQgaW5wdXRzXG4gICAgICAgICAgICAgICAgZWxzZSBpZiAoYnVuZGxlRW50cnkudmFsdWUgPj0gMCAmJiAhc3BlbnRBbHJlYWR5QWRkZWQgJiYgIWlzUmVtYWluZGVyKSB7XG5cbiAgICAgICAgICAgICAgICAgICAgY2F0ZWdvcml6ZWQucmVjZWl2ZWQucHVzaChidW5kbGUpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cbiAgICAgICAgfSlcbiAgICB9KVxuXG4gICAgcmV0dXJuIGNhdGVnb3JpemVkO1xufVxuXG5cbi8qKlxuKiAgIFZhbGlkYXRlcyB0aGUgc2lnbmF0dXJlc1xuKlxuKiAgIEBtZXRob2QgdmFsaWRhdGVTaWduYXR1cmVzXG4qICAgQHBhcmFtIHthcnJheX0gc2lnbmVkQnVuZGxlXG4qICAgQHBhcmFtIHtzdHJpbmd9IGlucHV0QWRkcmVzc1xuKiAgIEByZXR1cm5zIHtib29sfVxuKiovXG52YXIgdmFsaWRhdGVTaWduYXR1cmVzID0gZnVuY3Rpb24oc2lnbmVkQnVuZGxlLCBpbnB1dEFkZHJlc3MpIHtcblxuXG4gICAgdmFyIGJ1bmRsZUhhc2g7XG4gICAgdmFyIHNpZ25hdHVyZUZyYWdtZW50cyA9IFtdO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzaWduZWRCdW5kbGUubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICBpZiAoc2lnbmVkQnVuZGxlW2ldLmFkZHJlc3MgPT09IGlucHV0QWRkcmVzcykge1xuXG4gICAgICAgICAgICBidW5kbGVIYXNoID0gc2lnbmVkQnVuZGxlW2ldLmJ1bmRsZTtcblxuICAgICAgICAgICAgLy8gaWYgd2UgcmVhY2hlZCByZW1haW5kZXIgYnVuZGxlXG4gICAgICAgICAgICBpZiAoaW5wdXRWYWxpZGF0b3IuaXNOaW5lc1RyeXRlcyhzaWduZWRCdW5kbGVbaV0uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50KSkge1xuICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBzaWduYXR1cmVGcmFnbWVudHMucHVzaChzaWduZWRCdW5kbGVbaV0uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50KVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgaWYgKCFidW5kbGVIYXNoKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gU2lnbmluZy52YWxpZGF0ZVNpZ25hdHVyZXMoaW5wdXRBZGRyZXNzLCBzaWduYXR1cmVGcmFnbWVudHMsIGJ1bmRsZUhhc2gpO1xufVxuXG5cbi8qKlxuKiAgIENoZWNrcyBpcyBhIEJ1bmRsZSBpcyB2YWxpZC4gVmFsaWRhdGVzIHNpZ25hdHVyZXMgYW5kIG92ZXJhbGwgc3RydWN0dXJlLiBIYXMgdG8gYmUgdGFpbCB0eCBmaXJzdC5cbipcbiogICBAbWV0aG9kIGlzVmFsaWRCdW5kbGVcbiogICBAcGFyYW0ge2FycmF5fSBidW5kbGVcbiogICBAcmV0dXJucyB7Ym9vbH0gdmFsaWRcbioqL1xudmFyIGlzQnVuZGxlID0gZnVuY3Rpb24oYnVuZGxlKSB7XG5cbiAgICAvLyBJZiBub3QgY29ycmVjdCBidW5kbGVcbiAgICBpZiAoIWlucHV0VmFsaWRhdG9yLmlzQXJyYXlPZlR4T2JqZWN0cyhidW5kbGUpKSByZXR1cm4gZmFsc2U7XG5cbiAgICB2YXIgdG90YWxTdW0gPSAwLCBsYXN0SW5kZXgsIGJ1bmRsZUhhc2ggPSBidW5kbGVbMF0uYnVuZGxlO1xuXG4gICAgLy8gUHJlcGFyZSB0byBhYnNvcmIgdHhzIGFuZCBnZXQgYnVuZGxlSGFzaFxuICAgIHZhciBidW5kbGVGcm9tVHhzID0gW107XG5cbiAgICB2YXIga2VybCA9IG5ldyBLZXJsKCk7XG4gICAga2VybC5pbml0aWFsaXplKCk7XG5cbiAgICAvLyBQcmVwYXJlIGZvciBzaWduYXR1cmUgdmFsaWRhdGlvblxuICAgIHZhciBzaWduYXR1cmVzVG9WYWxpZGF0ZSA9IFtdO1xuXG4gICAgYnVuZGxlLmZvckVhY2goZnVuY3Rpb24oYnVuZGxlVHgsIGluZGV4KSB7XG5cbiAgICAgICAgdG90YWxTdW0gKz0gYnVuZGxlVHgudmFsdWU7XG5cbiAgICAgICAgLy8gY3VycmVudEluZGV4IGhhcyB0byBiZSBlcXVhbCB0byB0aGUgaW5kZXggaW4gdGhlIGFycmF5XG4gICAgICAgIGlmIChidW5kbGVUeC5jdXJyZW50SW5kZXggIT09IGluZGV4KSByZXR1cm4gZmFsc2U7XG5cbiAgICAgICAgLy8gR2V0IHRoZSB0cmFuc2FjdGlvbiB0cnl0ZXNcbiAgICAgICAgdmFyIHRoaXNUeFRyeXRlcyA9IHRyYW5zYWN0aW9uVHJ5dGVzKGJ1bmRsZVR4KTtcblxuICAgICAgICAvLyBBYnNvcmIgYnVuZGxlIGhhc2ggKyB2YWx1ZSArIHRpbWVzdGFtcCArIGxhc3RJbmRleCArIGN1cnJlbnRJbmRleCB0cnl0ZXMuXG4gICAgICAgIHZhciB0aGlzVHhUcml0cyA9IENvbnZlcnRlci50cml0cyh0aGlzVHhUcnl0ZXMuc2xpY2UoMjE4NywgMjE4NyArIDE2MikpO1xuICAgICAgICBrZXJsLmFic29yYih0aGlzVHhUcml0cywgMCwgdGhpc1R4VHJpdHMubGVuZ3RoKTtcblxuICAgICAgICAvLyBDaGVjayBpZiBpbnB1dCB0cmFuc2FjdGlvblxuICAgICAgICBpZiAoYnVuZGxlVHgudmFsdWUgPCAwKSB7XG4gICAgICAgICAgICB2YXIgdGhpc0FkZHJlc3MgPSBidW5kbGVUeC5hZGRyZXNzO1xuXG4gICAgICAgICAgICB2YXIgbmV3U2lnbmF0dXJlVG9WYWxpZGF0ZSA9IHtcbiAgICAgICAgICAgICAgICAnYWRkcmVzcyc6IHRoaXNBZGRyZXNzLFxuICAgICAgICAgICAgICAgICdzaWduYXR1cmVGcmFnbWVudHMnOiBBcnJheShidW5kbGVUeC5zaWduYXR1cmVNZXNzYWdlRnJhZ21lbnQpXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIC8vIEZpbmQgdGhlIHN1YnNlcXVlbnQgdHhzIHdpdGggdGhlIHJlbWFpbmluZyBzaWduYXR1cmUgZnJhZ21lbnRcbiAgICAgICAgICAgIGZvciAodmFyIGkgPSBpbmRleDsgaSA8IGJ1bmRsZS5sZW5ndGggLSAxOyBpKyspIHtcbiAgICAgICAgICAgICAgICB2YXIgbmV3QnVuZGxlVHggPSBidW5kbGVbaSArIDFdO1xuXG4gICAgICAgICAgICAgICAgLy8gQ2hlY2sgaWYgbmV3IHR4IGlzIHBhcnQgb2YgdGhlIHNpZ25hdHVyZSBmcmFnbWVudFxuICAgICAgICAgICAgICAgIGlmIChuZXdCdW5kbGVUeC5hZGRyZXNzID09PSB0aGlzQWRkcmVzcyAmJiBuZXdCdW5kbGVUeC52YWx1ZSA9PT0gMCkge1xuICAgICAgICAgICAgICAgICAgICBuZXdTaWduYXR1cmVUb1ZhbGlkYXRlLnNpZ25hdHVyZUZyYWdtZW50cy5wdXNoKG5ld0J1bmRsZVR4LnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudCk7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBzaWduYXR1cmVzVG9WYWxpZGF0ZS5wdXNoKG5ld1NpZ25hdHVyZVRvVmFsaWRhdGUpO1xuICAgICAgICB9XG4gICAgfSk7XG5cbiAgICAvLyBDaGVjayBmb3IgdG90YWwgc3VtLCBpZiBub3QgZXF1YWwgMCByZXR1cm4gZXJyb3JcbiAgICBpZiAodG90YWxTdW0gIT09IDApIHJldHVybiBmYWxzZTtcblxuICAgIC8vIGdldCB0aGUgYnVuZGxlIGhhc2ggZnJvbSB0aGUgYnVuZGxlIHRyYW5zYWN0aW9uc1xuICAgIGtlcmwuc3F1ZWV6ZShidW5kbGVGcm9tVHhzLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcbiAgICB2YXIgYnVuZGxlRnJvbVR4cyA9IENvbnZlcnRlci50cnl0ZXMoYnVuZGxlRnJvbVR4cyk7XG5cbiAgICAvLyBDaGVjayBpZiBidW5kbGUgaGFzaCBpcyB0aGUgc2FtZSBhcyByZXR1cm5lZCBieSB0eCBvYmplY3RcbiAgICBpZiAoYnVuZGxlRnJvbVR4cyAhPT0gYnVuZGxlSGFzaCkgcmV0dXJuIGZhbHNlO1xuXG4gICAgLy8gTGFzdCB0eCBpbiB0aGUgYnVuZGxlIHNob3VsZCBoYXZlIGN1cnJlbnRJbmRleCA9PT0gbGFzdEluZGV4XG4gICAgaWYgKGJ1bmRsZVtidW5kbGUubGVuZ3RoIC0gMV0uY3VycmVudEluZGV4ICE9PSBidW5kbGVbYnVuZGxlLmxlbmd0aCAtIDFdLmxhc3RJbmRleCkgcmV0dXJuIGZhbHNlO1xuXG4gICAgLy8gVmFsaWRhdGUgdGhlIHNpZ25hdHVyZXNcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHNpZ25hdHVyZXNUb1ZhbGlkYXRlLmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgdmFyIGlzVmFsaWRTaWduYXR1cmUgPSBTaWduaW5nLnZhbGlkYXRlU2lnbmF0dXJlcyhzaWduYXR1cmVzVG9WYWxpZGF0ZVtpXS5hZGRyZXNzLCBzaWduYXR1cmVzVG9WYWxpZGF0ZVtpXS5zaWduYXR1cmVGcmFnbWVudHMsIGJ1bmRsZUhhc2gpO1xuXG4gICAgICAgIGlmICghaXNWYWxpZFNpZ25hdHVyZSkgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgICBpbnB1dFZhbGlkYXRvciAgICAgIDogaW5wdXRWYWxpZGF0b3IsICAgIFxuICAgIGNvbnZlcnRVbml0cyAgICAgICAgOiBjb252ZXJ0VW5pdHMsXG4gICAgYWRkQ2hlY2tzdW0gICAgICAgICA6IGFkZENoZWNrc3VtLFxuICAgIG5vQ2hlY2tzdW0gICAgICAgICAgOiBub0NoZWNrc3VtLFxuICAgIGlzVmFsaWRDaGVja3N1bSAgICAgOiBpc1ZhbGlkQ2hlY2tzdW0sXG4gICAgdHJhbnNhY3Rpb25PYmplY3QgICA6IHRyYW5zYWN0aW9uT2JqZWN0LFxuICAgIHRyYW5zYWN0aW9uVHJ5dGVzICAgOiB0cmFuc2FjdGlvblRyeXRlcyxcbiAgICBjYXRlZ29yaXplVHJhbnNmZXJzIDogY2F0ZWdvcml6ZVRyYW5zZmVycyxcbiAgICB0b1RyeXRlcyAgICAgICAgICAgIDogYXNjaWkudG9Ucnl0ZXMsXG4gICAgZnJvbVRyeXRlcyAgICAgICAgICA6IGFzY2lpLmZyb21Ucnl0ZXMsXG4gICAgZXh0cmFjdEpzb24gICAgICAgICA6IGV4dHJhY3RKc29uLFxuICAgIHZhbGlkYXRlU2lnbmF0dXJlcyAgOiB2YWxpZGF0ZVNpZ25hdHVyZXMsXG4gICAgaXNCdW5kbGUgICAgICAgICAgICA6IGlzQnVuZGxlXG59XG4iLCJjb25zdCBpbml0R0wgPSByZXF1aXJlKCcuL2luaXRHTCcpO1xuY29uc3QgbmV3QnVmZmVyID0gcmVxdWlyZSgnLi9uZXdCdWZmZXInKTtcbmNvbnN0IGNyZWF0ZVRleHR1cmUgPSByZXF1aXJlKCcuL3RleHR1cmUnKTtcbmNvbnN0IFNoYWRlckNvZGUgPSByZXF1aXJlKCcuL3NoYWRlcmNvZGUnKTtcblxuZnVuY3Rpb24gX2ZyYW1lQnVmZmVyU2V0VGV4dHVyZSAoZ2wsIGZibywgblRleHR1cmUsIGRpbSkge1xuICBnbC5iaW5kRnJhbWVidWZmZXIoZ2wuRlJBTUVCVUZGRVIsIGZibyk7XG4gIC8vIFR5cGVzIGFycmF5cyBzcGVlZCB0aGlzIHVwIHRyZW1lbmRvdXNseS5cbiAgLy92YXIgblRleHR1cmUgPSBjcmVhdGVUZXh0dXJlKGdsLCBuZXcgSW50MzJBcnJheShsZW5ndGgpLCBkaW0pO1xuXG4gIGdsLmZyYW1lYnVmZmVyVGV4dHVyZTJEKGdsLkZSQU1FQlVGRkVSLCBnbC5DT0xPUl9BVFRBQ0hNRU5UMCwgZ2wuVEVYVFVSRV8yRCwgblRleHR1cmUsIDApO1xuXG4gIC8vIFRlc3QgZm9yIG1vYmlsZSBidWcgTUROLT5XZWJHTF9iZXN0X3ByYWN0aWNlcywgYnVsbGV0IDdcbiAgdmFyIGZyYW1lQnVmZmVyU3RhdHVzID0gKGdsLmNoZWNrRnJhbWVidWZmZXJTdGF0dXMoZ2wuRlJBTUVCVUZGRVIpID09IGdsLkZSQU1FQlVGRkVSX0NPTVBMRVRFKTtcblxuICBpZiAoIWZyYW1lQnVmZmVyU3RhdHVzKVxuICAgIHRocm93IG5ldyBFcnJvcigndHVyYm9qczogRXJyb3IgYXR0YWNoaW5nIGZsb2F0IHRleHR1cmUgdG8gZnJhbWVidWZmZXIuIFlvdXIgZGV2aWNlIGlzIHByb2JhYmx5IGluY29tcGF0aWJsZS4gRXJyb3IgaW5mbzogJyArIGZyYW1lQnVmZmVyU3RhdHVzLm1lc3NhZ2UpO1xufVxuZnVuY3Rpb24gYWxsb2MgKHN6KSB7XG4gIC8vIEEgc2FuZSBsaW1pdCBmb3IgbW9zdCBHUFVzIG91dCB0aGVyZS5cbiAgLy8gSlMgZmFsbHMgYXBhcnQgYmVmb3JlIEdMU0wgbGltaXRzIGNvdWxkIGV2ZXIgYmUgcmVhY2hlZC5cblxuICB2YXIgbnMgPSBNYXRoLnBvdyhNYXRoLnBvdygyLCBNYXRoLmNlaWwoTWF0aC5sb2coc3opIC8gMS4zODYpIC0gMSksIDIpO1xuICByZXR1cm4ge1xuICAgIC8vZGF0YSA6IG5ldyBJbnQzMkFycmF5KG5zICogMTYpLFxuICAgIGRhdGEgOiBuZXcgSW50MzJBcnJheShzeiksXG4gICAgbGVuZ3RoIDogc3pcbiAgfTtcbn1cbmNvbnN0IF9iaW5kQnVmZmVycyA9IChnbCwgYnVmZmVycywgYXR0cmliKSA9PiB7XG4gIGdsLmJpbmRCdWZmZXIoZ2wuQVJSQVlfQlVGRkVSLCBidWZmZXJzLnRleHR1cmUpO1xuICBnbC5lbmFibGVWZXJ0ZXhBdHRyaWJBcnJheShhdHRyaWIudGV4dHVyZSk7XG4gIGdsLnZlcnRleEF0dHJpYlBvaW50ZXIoYXR0cmliLnRleHR1cmUsIDIsIGdsLkZMT0FULCBmYWxzZSwgMCwgMCk7XG4gIGdsLmJpbmRCdWZmZXIoZ2wuQVJSQVlfQlVGRkVSLCBidWZmZXJzLnBvc2l0aW9uKTtcbiAgZ2wuZW5hYmxlVmVydGV4QXR0cmliQXJyYXkoYXR0cmliLnBvc2l0aW9uKTtcbiAgZ2wudmVydGV4QXR0cmliUG9pbnRlcihhdHRyaWIucG9zaXRpb24sIDIsIGdsLkZMT0FULCBmYWxzZSwgMCwgMCk7XG4gIGdsLmJpbmRCdWZmZXIoZ2wuRUxFTUVOVF9BUlJBWV9CVUZGRVIsIGJ1ZmZlcnMuaW5kZXgpO1xufVxuY29uc3QgX2NyZWF0ZVZlcnRleFNoYWRlciA9IChnbCkgPT4ge1xuICB2YXIgdmVydGV4U2hhZGVyID0gZ2wuY3JlYXRlU2hhZGVyKGdsLlZFUlRFWF9TSEFERVIpO1xuICBnbC5zaGFkZXJTb3VyY2UodmVydGV4U2hhZGVyLCBTaGFkZXJDb2RlLnZlcnRleFNoYWRlckNvZGUpO1xuICBnbC5jb21waWxlU2hhZGVyKHZlcnRleFNoYWRlcik7XG5cbiAgLy8gVGhpcyBzaG91bGQgbm90IGZhaWwuXG4gIGlmICghZ2wuZ2V0U2hhZGVyUGFyYW1ldGVyKHZlcnRleFNoYWRlciwgZ2wuQ09NUElMRV9TVEFUVVMpKVxuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgIFwiXFxudHVyYm9qczogQ291bGQgbm90IGJ1aWxkIGludGVybmFsIHZlcnRleCBzaGFkZXIgKGZhdGFsKS5cXG5cIiArIFwiXFxuXCIgK1xuICAgICAgXCJJTkZPOiA+UkVQT1JUPCBUSElTLiBUaGF0J3Mgb3VyIGZhdWx0IVxcblwiICsgXCJcXG5cIiArXG4gICAgICBcIi0tLSBDT0RFIERVTVAgLS0tXFxuXCIgKyBTaGFkZXJDb2RlLnZlcnRleFNoYWRlckNvZGUgKyBcIlxcblxcblwiICtcbiAgICAgIFwiLS0tIEVSUk9SIExPRyAtLS1cXG5cIiArIGdsLmdldFNoYWRlckluZm9Mb2codmVydGV4U2hhZGVyKVxuICAgICk7XG4gIHJldHVybiB2ZXJ0ZXhTaGFkZXI7XG59XG5jb25zdCBfY3JlYXRlRnJhZ21lbnRTaGFkZXIgPSAoZ2wsIGNvZGUpID0+IHtcbiAgdmFyIGZyYWdtZW50U2hhZGVyID0gZ2wuY3JlYXRlU2hhZGVyKGdsLkZSQUdNRU5UX1NIQURFUik7XG5cbiAgZ2wuc2hhZGVyU291cmNlKGZyYWdtZW50U2hhZGVyLCBTaGFkZXJDb2RlLnN0ZGxpYiArIGNvZGUpO1xuXG4gIGdsLmNvbXBpbGVTaGFkZXIoZnJhZ21lbnRTaGFkZXIpO1xuICAvLyBVc2UgdGhpcyBvdXRwdXQgdG8gZGVidWcgdGhlIHNoYWRlclxuICAvLyBLZWVwIGluIG1pbmQgdGhhdCBXZWJHTCBHTFNMIGlzICoqbXVjaCoqIHN0cmljdGVyIHRoYW4gZS5nLiBPcGVuR0wgR0xTTFxuICBpZiAoIWdsLmdldFNoYWRlclBhcmFtZXRlcihmcmFnbWVudFNoYWRlciwgZ2wuQ09NUElMRV9TVEFUVVMpKSB7XG4gICAgdmFyIExPQyA9IGNvZGUuc3BsaXQoJ1xcbicpO1xuICAgIHZhciBkYmdNc2cgPSBcIkVSUk9SOiBDb3VsZCBub3QgYnVpbGQgc2hhZGVyIChmYXRhbCkuXFxuXFxuLS0tLS0tLS0tLS0tLS0tLS0tIEtFUk5FTCBDT0RFIERVTVAgLS0tLS0tLS0tLS0tLS0tLS0tXFxuXCJcblxuICAgIGZvciAodmFyIG5sID0gMDsgbmwgPCBMT0MubGVuZ3RoOyBubCsrKVxuICAgICAgZGJnTXNnICs9IChTaGFkZXJDb2RlLnN0ZGxpYi5zcGxpdCgnXFxuJykubGVuZ3RoICsgbmwpICsgXCI+IFwiICsgTE9DW25sXSArIFwiXFxuXCI7XG5cbiAgICBkYmdNc2cgKz0gXCJcXG4tLS0tLS0tLS0tLS0tLS0tLS0tLS0gRVJST1IgIExPRyAtLS0tLS0tLS0tLS0tLS0tLS0tLS1cXG5cIiArIGdsLmdldFNoYWRlckluZm9Mb2coZnJhZ21lbnRTaGFkZXIpXG5cbiAgICB0aHJvdyBuZXcgRXJyb3IoZGJnTXNnKTtcbiAgfVxuICByZXR1cm4gZnJhZ21lbnRTaGFkZXI7XG59XG5jb25zdCBfZmluaXNoUnVuICA9IChnbCkgPT4ge1xuICBnbC5iaW5kVmVydGV4QXJyYXkobnVsbCk7XG4gIGdsLmJpbmRUZXh0dXJlKGdsLlRFWFRVUkVfMkQsIG51bGwpO1xuICBnbC5iaW5kRnJhbWVidWZmZXIoZ2wuRlJBTUVCVUZGRVIsIG51bGwpO1xufVxuY29uc3QgV2ViR0xXb3JrZXIgPSAobCwgcykgPT4ge1xuXG4gIGxldCB3b3JrZXIgPSBuZXcgT2JqZWN0KCk7XG4gIHdvcmtlci5nbCA9IGluaXRHTCgpO1xuICBsZXQgZ2wgPSB3b3JrZXIuZ2w7XG5cbiAgd29ya2VyLmRpbSA9IHtcbiAgICB4OiBsLFxuICAgIHk6IDBcbiAgfTtcbiAgY29uc3QgTUFYSU1BR0VTSVpFID0gTWF0aC5wb3coZ2wuTUFYX1RFWFRVUkVfU0laRSwgMikgKiAwLjUwO1xuICBjb25zdCBJTUFHRV9TSVpFPSBNYXRoLmZsb29yKE1BWElNQUdFU0laRSAvIHdvcmtlci5kaW0ueCAvIHMgKSAqIHdvcmtlci5kaW0ueCAqIHM7XG4gIHdvcmtlci5kaW0ueSA9IElNQUdFX1NJWkUgLyB3b3JrZXIuZGltLnggLyBzIDtcbiAgbGV0IGxlbmd0aCA9IElNQUdFX1NJWkU7XG5cblxuICB3b3JrZXIucHJvZ3JhbXMgPSBuZXcgTWFwKCk7XG4gIHdvcmtlci5pcHQgPSBhbGxvYyhsZW5ndGgpO1xuXG4gIC8vIEdQVSB0ZXh0dXJlIGJ1ZmZlciA9IGZyb20gSlMgdHlwZWQgYXJyYXlcbiAgd29ya2VyLmJ1ZmZlcnMgPSB7XG4gICAgcG9zaXRpb24gOiBuZXdCdWZmZXIoZ2wsIFsgLTEsIC0xLCAxLCAtMSwgMSwgMSwgLTEsIDEgXSksXG4gICAgdGV4dHVyZSAgOiBuZXdCdWZmZXIoZ2wsIFsgIDAsICAwLCAxLCAgMCwgMSwgMSwgIDAsIDEgXSksXG4gICAgaW5kZXggICAgOiBuZXdCdWZmZXIoZ2wsIFsgIDEsICAyLCAwLCAgMywgMCwgMiBdLCBVaW50MTZBcnJheSwgZ2wuRUxFTUVOVF9BUlJBWV9CVUZGRVIpXG4gIH07XG5cbiAgd29ya2VyLmF0dHJpYiA9IHtcbiAgICBwb3NpdGlvbjogMCxcbiAgICB0ZXh0dXJlOiAxXG4gIH07XG5cbiAgd29ya2VyLnZhbyA9IGdsLmNyZWF0ZVZlcnRleEFycmF5KCk7XG4gIGdsLmJpbmRWZXJ0ZXhBcnJheSh3b3JrZXIudmFvKTtcbiAgX2JpbmRCdWZmZXJzKGdsLCB3b3JrZXIuYnVmZmVycywgd29ya2VyLmF0dHJpYik7XG4gIGdsLmJpbmRWZXJ0ZXhBcnJheShudWxsKTtcbiAgd29ya2VyLnZlcnRleFNoYWRlciA9IF9jcmVhdGVWZXJ0ZXhTaGFkZXIoZ2wpO1xuICB3b3JrZXIuZnJhbWVidWZmZXIgPSBnbC5jcmVhdGVGcmFtZWJ1ZmZlcigpO1xuICB3b3JrZXIudGV4dHVyZTAgPSBjcmVhdGVUZXh0dXJlKGdsLCB3b3JrZXIuaXB0LmRhdGEsIHdvcmtlci5kaW0pO1xuICB3b3JrZXIudGV4dHVyZTEgPSBjcmVhdGVUZXh0dXJlKGdsLCBuZXcgSW50MzJBcnJheShsZW5ndGgpLCB3b3JrZXIuZGltKTtcbiAgcmV0dXJuIHdvcmtlcjtcbn1cbm1vZHVsZS5leHBvcnRzID0ge1xuICB3b3JrZXI6IFdlYkdMV29ya2VyLFxuICBhZGRQcm9ncmFtOiAod29ya2VyLCBuYW1lLCBjb2RlLCAuLi51bmlmb3JtcykgPT4ge1xuICAgIGxldCBnbCA9IHdvcmtlci5nbDtcbiAgICBsZXQgdmVydGV4U2hhZGVyID0gd29ya2VyLnZlcnRleFNoYWRlcjtcblxuICAgIHZhciBmcmFnbWVudFNoYWRlciA9IF9jcmVhdGVGcmFnbWVudFNoYWRlcih3b3JrZXIuZ2wsIGNvZGUpO1xuICAgIHZhciBwcm9ncmFtID0gZ2wuY3JlYXRlUHJvZ3JhbSgpO1xuXG4gICAgZ2wuYXR0YWNoU2hhZGVyKHByb2dyYW0sIHZlcnRleFNoYWRlcik7XG4gICAgZ2wuYXR0YWNoU2hhZGVyKHByb2dyYW0sIGZyYWdtZW50U2hhZGVyKTtcbiAgICBnbC5iaW5kQXR0cmliTG9jYXRpb24ocHJvZ3JhbSwgd29ya2VyLmF0dHJpYi5wb3NpdGlvbiwgJ3Bvc2l0aW9uJyk7XG4gICAgZ2wuYmluZEF0dHJpYkxvY2F0aW9uKHByb2dyYW0sIHdvcmtlci5hdHRyaWIudGV4dHVyZSwgJ3RleHR1cmUnKTtcbiAgICBnbC5saW5rUHJvZ3JhbShwcm9ncmFtKTtcbiAgICB2YXIgdV92YXJzID0gbmV3IE1hcCgpO1xuICAgIGZvcih2YXIgdmFyaWFibGUgb2YgdW5pZm9ybXMpIHtcbiAgICAgIHVfdmFycy5zZXQodmFyaWFibGUsIGdsLmdldFVuaWZvcm1Mb2NhdGlvbihwcm9ncmFtLCB2YXJpYWJsZSkpO1xuICAgIH1cbiAgICBpZighIXdvcmtlci5wcm9ncmFtcy5nZXQobmFtZSkpIHtcbiAgICAgIGNvbnNvbGUubG9nKFwicHJvZ3JhbSBleGlzdHNcIik7XG4gICAgfVxuICAgIHdvcmtlci5wcm9ncmFtcy5zZXQobmFtZSwge3Byb2dyYW0sIHVfdmFyc30pO1xuICB9LFxuICAgIC8qXG4gICAgdXNlOiAobmFtZSkgPT4ge1xuICB9LFxuICAqL1xuICBydW46ICh3b3JrZXIsIG5hbWUsIGNvdW50LCAuLi51bmlmb3JtcykgPT4ge1xuICAgIGxldCBnbCA9IHdvcmtlci5nbDtcbiAgICBsZXQgaW5mbyA9IHdvcmtlci5wcm9ncmFtcy5nZXQobmFtZSk7XG4gICAgbGV0IHByb2dyYW0gPSBpbmZvLnByb2dyYW07XG4gICAgbGV0IHVfdmFycyA9IGluZm8udV92YXJzO1xuICAgIGlmKHByb2dyYW0gPT09IG51bGwpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJObyBTdWNoIFByb2dyYW0hXCIpO1xuXG4gICAgaWYgKCFnbC5nZXRQcm9ncmFtUGFyYW1ldGVyKHByb2dyYW0sIGdsLkxJTktfU1RBVFVTKSlcbiAgICAgIHRocm93IG5ldyBFcnJvcigndHVyYm9qczogRmFpbGVkIHRvIGxpbmsgR0xTTCBwcm9ncmFtIGNvZGUuJyk7XG5cbiAgICB2YXIgdVRleHR1cmUgPSBnbC5nZXRVbmlmb3JtTG9jYXRpb24ocHJvZ3JhbSwgJ3VfdGV4dHVyZScpO1xuICAgIGdsLnVzZVByb2dyYW0ocHJvZ3JhbSk7XG5cbiAgICBjb3VudCA9IGNvdW50IHx8IDE7XG4gICAgd2hpbGUoY291bnQtLSA+IDApIHtcbiAgICAgIGdsLmJpbmRUZXh0dXJlKGdsLlRFWFRVUkVfMkQsIHdvcmtlci50ZXh0dXJlMCk7XG4gICAgICBnbC5hY3RpdmVUZXh0dXJlKGdsLlRFWFRVUkUwKTtcbiAgICAgIGdsLnVuaWZvcm0xaSh1VGV4dHVyZSwgMCk7XG5cbiAgICAgIGdsLnZpZXdwb3J0KDAsIDAsIHdvcmtlci5kaW0ueCwgd29ya2VyLmRpbS55KTtcbiAgICAgIF9mcmFtZUJ1ZmZlclNldFRleHR1cmUoZ2wsIHdvcmtlci5mcmFtZWJ1ZmZlciwgd29ya2VyLnRleHR1cmUxLCB3b3JrZXIuZGltKTsgLy9uZXdcbiAgICAgIGdsLmJpbmRWZXJ0ZXhBcnJheSh3b3JrZXIudmFvKTtcbiAgICAgIGZvcih2YXIgdV92IG9mIHVuaWZvcm1zKSB7XG4gICAgICAgIGdsLnVuaWZvcm0xaSh1X3ZhcnMuZ2V0KHVfdi5uKSwgdV92LnYpO1xuICAgICAgfVxuICAgICAgZ2wuZHJhd0VsZW1lbnRzKGdsLlRSSUFOR0xFUywgNiwgZ2wuVU5TSUdORURfU0hPUlQsIDApO1xuICAgICAgbGV0IHRleDAgPSB3b3JrZXIudGV4dHVyZTA7XG4gICAgICB3b3JrZXIudGV4dHVyZTAgPSB3b3JrZXIudGV4dHVyZTE7XG4gICAgICB3b3JrZXIudGV4dHVyZTEgPSB0ZXgwO1xuICAgIH1cblxuICAgIF9maW5pc2hSdW4oZ2wpO1xuICB9LFxuICByZWFkRGF0YTogKHdvcmtlciwgeCx5LE4sTSkgPT4ge1xuICAgIGxldCBnbCA9IHdvcmtlci5nbDtcbiAgICB4ID0geCB8fCAwO1xuICAgIHkgPSB5IHx8IDA7XG4gICAgTiA9IE4gfHwgd29ya2VyLmRpbS54O1xuICAgIE0gPSBNIHx8IHdvcmtlci5kaW0ueTtcbiAgICBnbC5iaW5kRnJhbWVidWZmZXIoZ2wuRlJBTUVCVUZGRVIsIHdvcmtlci5mcmFtZWJ1ZmZlcik7XG4gICAgZ2wucmVhZFBpeGVscyh4LCB5LCBOLCBNLCBnbC5SR0JBX0lOVEVHRVIsIGdsLklOVCwgd29ya2VyLmlwdC5kYXRhKTtcbiAgICBnbC5iaW5kRnJhbWVidWZmZXIoZ2wuRlJBTUVCVUZGRVIsIG51bGwpO1xuICAgIHJldHVybiB3b3JrZXIuaXB0LmRhdGEuc3ViYXJyYXkoMCwgd29ya2VyLmlwdC5sZW5ndGgpO1xuICB9LFxuICB3cml0ZURhdGE6ICh3b3JrZXIsIGRhdGEpID0+IHtcbiAgICBsZXQgZ2wgPSB3b3JrZXIuZ2w7XG4gICAgZ2wuYmluZFRleHR1cmUoZ2wuVEVYVFVSRV8yRCwgd29ya2VyLnRleHR1cmUwKTtcbiAgICBnbC50ZXhJbWFnZTJEKGdsLlRFWFRVUkVfMkQsIDAsIGdsLlJHQkEzMkksd29ya2VyLmRpbS54LHdvcmtlci5kaW0ueSwgMCwgZ2wuUkdCQV9JTlRFR0VSLCBnbC5JTlQsIGRhdGEpO1xuICAgIGdsLmJpbmRUZXh0dXJlKGdsLlRFWFRVUkVfMkQsIG51bGwpO1xuICB9XG59XG4iLCJtb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uICgpIHtcbiAgdmFyIGNhbnZhcyA9IGRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2NhbnZhcycpO1xuICAvL3ZhciBjYW52YXMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYycpO1xuICB2YXIgZ2wgPSBudWxsO1xuICB2YXIgYXR0ciA9IHthbHBoYSA6IGZhbHNlLCBhbnRpYWxpYXMgOiBmYWxzZX07XG5cbiAgLy8gVHJ5IHRvIGdyYWIgdGhlIHN0YW5kYXJkIGNvbnRleHQuIElmIGl0IGZhaWxzLCBmYWxsYmFjayB0byBleHBlcmltZW50YWwuXG4gIGdsID0gY2FudmFzLmdldENvbnRleHQoXCJ3ZWJnbDJcIiwgYXR0cikgfHwgY2FudmFzLmdldENvbnRleHQoXCJleHBlcmltZW50YWwtd2ViZ2wyXCIsIGF0dHIpO1xuXG4gIC8vIElmIHdlIGRvbid0IGhhdmUgYSBHTCBjb250ZXh0LCBnaXZlIHVwIG5vd1xuIGlmICghZ2wpIHsgLy8gZ2wgaW5zdGFuY2VvZiBXZWJHTFJlbmRlcmluZ0NvbnRleHQpXG4gICAgdGhyb3cgbmV3IEVycm9yKFwiVW5hYmxlIHRvIGluaXRpYWxpemUgV2ViR0wuIFlvdXIgYnJvd3NlciBtYXkgbm90IHN1cHBvcnQgaXQuXCIpO1xuIH1cblxuICByZXR1cm4gZ2w7XG59XG4iLCJtb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIChnbCwgZGF0YSwgZiwgZSkge1xuICB2YXIgYnVmID0gZ2wuY3JlYXRlQnVmZmVyKCk7XG5cbiAgZ2wuYmluZEJ1ZmZlcigoZSB8fCBnbC5BUlJBWV9CVUZGRVIpLCBidWYpO1xuICBnbC5idWZmZXJEYXRhKChlIHx8IGdsLkFSUkFZX0JVRkZFUiksIG5ldyAoZiB8fCBGbG9hdDMyQXJyYXkpKGRhdGEpLCBnbC5TVEFUSUNfRFJBVyk7XG5cbiAgcmV0dXJuIGJ1Zjtcbn1cbiIsIm1vZHVsZS5leHBvcnRzID0ge1xuIHZlcnRleFNoYWRlckNvZGU6XG4gIGAjdmVyc2lvbiAzMDAgZXNcbmxheW91dChsb2NhdGlvbiA9IDApIGluIHZlYzIgcG9zaXRpb247XG5sYXlvdXQobG9jYXRpb24gPSAxKSBpbiB2ZWMyIHRleHR1cmU7XG5vdXQgdmVjMiBwb3M7XG5cbnZvaWQgbWFpbih2b2lkKSB7XG4gIHBvcyA9IHRleHR1cmU7XG4gIGdsX1Bvc2l0aW9uID0gdmVjNChwb3NpdGlvbi54eSwgMC4wLCAxLjApO1xufWAsXG4gIHN0ZGxpYjpcbiAgYCN2ZXJzaW9uIDMwMCBlc1xucHJlY2lzaW9uIGhpZ2hwIGZsb2F0O1xucHJlY2lzaW9uIGhpZ2hwIGludDtcbnByZWNpc2lvbiBoaWdocCBpc2FtcGxlcjJEO1xudW5pZm9ybSBpc2FtcGxlcjJEIHVfdGV4dHVyZTtcbmluIHZlYzIgcG9zO1xub3V0IGl2ZWM0IGNvbG9yO1xuLy9vdXQgaW50IGlzRmluaXNoZWQ7XG5cbnZlYzIgc2l6ZTtcbml2ZWMyIG15X2Nvb3JkO1xuXG52b2lkIGluaXQodm9pZCkge1xuICAvL3NpemUgPSB2ZWMyKHRleHR1cmVTaXplKHVfdGV4dHVyZSwgMCkgLSAxKTtcbiAgc2l6ZSA9IHZlYzIodGV4dHVyZVNpemUodV90ZXh0dXJlLCAwKSk7XG4gIG15X2Nvb3JkID0gaXZlYzIocG9zICogc2l6ZSk7XG59XG5cbml2ZWM0IHJlYWQodm9pZCkge1xuICByZXR1cm4gdGV4dHVyZSh1X3RleHR1cmUsIHBvcyk7XG59XG5cbml2ZWM0IHJlYWRfYXQoaXZlYzIgY29vcmQpIHtcbiAgcmV0dXJuIHRleGVsRmV0Y2godV90ZXh0dXJlLCBjb29yZCwgMCk7XG59XG5cbnZvaWQgY29tbWl0KGl2ZWM0IHZhbCkge1xuICBjb2xvciA9IHZhbDtcbn1cbmB9XG5cbiIsIi8vIFRyYW5zZmVyIGRhdGEgb250byBjbGFtcGVkIHRleHR1cmUgYW5kIHR1cm4gb2ZmIGFueSBmaWx0ZXJpbmdcbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gY3JlYXRlVGV4dHVyZShnbCwgZGF0YSwgZGltKSB7XG4gIHZhciB0ZXh0dXJlID0gZ2wuY3JlYXRlVGV4dHVyZSgpO1xuXG4gIGdsLmJpbmRUZXh0dXJlKGdsLlRFWFRVUkVfMkQsIHRleHR1cmUpO1xuICBnbC50ZXhQYXJhbWV0ZXJpKGdsLlRFWFRVUkVfMkQsIGdsLlRFWFRVUkVfV1JBUF9TLCBnbC5DTEFNUF9UT19FREdFKTtcbiAgZ2wudGV4UGFyYW1ldGVyaShnbC5URVhUVVJFXzJELCBnbC5URVhUVVJFX1dSQVBfVCwgZ2wuQ0xBTVBfVE9fRURHRSk7XG4gIGdsLnRleFBhcmFtZXRlcmkoZ2wuVEVYVFVSRV8yRCwgZ2wuVEVYVFVSRV9NSU5fRklMVEVSLCBnbC5ORUFSRVNUKTtcbiAgZ2wudGV4UGFyYW1ldGVyaShnbC5URVhUVVJFXzJELCBnbC5URVhUVVJFX01BR19GSUxURVIsIGdsLk5FQVJFU1QpO1xuICBnbC50ZXhJbWFnZTJEKGdsLlRFWFRVUkVfMkQsIDAsIGdsLlJHQkEzMkksIGRpbS54LCBkaW0ueSwgMCwgZ2wuUkdCQV9JTlRFR0VSLCBnbC5JTlQsIGRhdGEpO1xuICAvL2dsLnRleEltYWdlMkQoZ2wuVEVYVFVSRV8yRCwgMCwgZ2wuUkdCQTMyRiwgc2l6ZSwgc2l6ZSwgMCwgZ2wuUkdCQSwgZ2wuRkxPQVQsIGRhdGEpO1xuICAvL2dsLnRleFN0b3JhZ2UyRChnbC5URVhUVVJFXzJELCAxLCBnbC5SR0JBMzJGLCBzaXplLCBzaXplKTtcbiAgZ2wuYmluZFRleHR1cmUoZ2wuVEVYVFVSRV8yRCwgbnVsbCk7XG5cbiAgcmV0dXJuIHRleHR1cmU7XG59XG4iLCJjb25zdCBIQVNIX0xFTkdUSCA9IDI0MztcbmNvbnN0IElOVF9MRU5HVEggPSAyNztcbmNvbnN0IE5PTkNFX0xFTkdUSCA9IEhBU0hfTEVOR1RIIC8gMztcbmNvbnN0IFRJTUVTVEFNUF9TVEFSVCA9IE5PTkNFX0xFTkdUSDtcbmNvbnN0IFRJTUVTVEFNUF9MT1dFUl9CT1VORF9TVEFSVD0gVElNRVNUQU1QX1NUQVJUICsgSU5UX0xFTkdUSDtcbmNvbnN0IFRJTUVTVEFNUF9VUFBFUl9CT1VORF9TVEFSVCA9IFRJTUVTVEFNUF9MT1dFUl9CT1VORF9TVEFSVCArIElOVF9MRU5HVEg7XG5jb25zdCBOT05DRV9TVEFSVCA9IEhBU0hfTEVOR1RIIC0gTk9OQ0VfTEVOR1RIOyBcblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gIEhBU0hfTEVOR1RILFxuICBTVEFURV9MRU5HVEg6IEhBU0hfTEVOR1RIICogMyxcbiAgVElNRVNUQU1QX1NUQVJULFxuICBUSU1FU1RBTVBfTE9XRVJfQk9VTkRfU1RBUlQsXG4gIFRJTUVTVEFNUF9VUFBFUl9CT1VORF9TVEFSVCxcbiAgTk9OQ0VfU1RBUlQsXG4gIE5PTkNFX0xFTkdUSCxcbiAgSU5UX0xFTkdUSCxcbiAgTlVNQkVSX09GX1JPVU5EUzogODEsXG4gIFRSQU5TQUNUSU9OX0xFTkdUSDogSEFTSF9MRU5HVEggKiAzM1xufTtcbiIsImNvbnN0IENvbnN0ID0gcmVxdWlyZSgnLi9jb25zdGFudHMnKTtcblxuLyoqXG4gKiogICAgICBDcnlwdG9ncmFwaGljIHJlbGF0ZWQgZnVuY3Rpb25zIHRvIElPVEEncyBDdXJsIChzcG9uZ2UgZnVuY3Rpb24pXG4gKiovXG5cbmZ1bmN0aW9uIEN1cmwoc3RhdGUpIHtcbiAgLy8gdHJ1dGggdGFibGVcbiAgdGhpcy50cnV0aFRhYmxlID0gbmV3IEludDhBcnJheShbMSwgMCwgLTEsIDIsIDEsIC0xLCAwLCAyLCAtMSwgMSwgMF0pO1xuICB0aGlzLkhBU0hfTEVOR1RIID0gQ29uc3QuSEFTSF9MRU5HVEg7XG4gIHRoaXMuaW5pdGlhbGl6ZShzdGF0ZSk7XG4gIHRoaXMucmVzZXQoKTtcbn1cblxuLyoqXG4gKiAgIEluaXRpYWxpemVzIHRoZSBzdGF0ZSB3aXRoIDcyOSB0cml0c1xuICpcbiAqICAgQG1ldGhvZCBpbml0aWFsaXplXG4gKiovXG5DdXJsLnByb3RvdHlwZS5pbml0aWFsaXplID0gZnVuY3Rpb24oc3RhdGUsIGxlbmd0aCkge1xuXG4gIGlmIChzdGF0ZSkge1xuICAgIHRoaXMuc3RhdGUgPSBzdGF0ZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLnN0YXRlID0gbmV3IEludDhBcnJheShDb25zdC5TVEFURV9MRU5HVEgpO1xuICB9XG59XG5cbkN1cmwucHJvdG90eXBlLnJlc2V0ID0gZnVuY3Rpb24oKSB7XG4gIHRoaXMuc3RhdGUuZmlsbCgwKTtcbn1cblxuLyoqXG4gKiAgIFNwb25nZSBhYnNvcmIgZnVuY3Rpb25cbiAqXG4gKiAgIEBtZXRob2QgYWJzb3JiXG4gKiovXG5DdXJsLnByb3RvdHlwZS5hYnNvcmIgPSBmdW5jdGlvbih0cml0cywgb2Zmc2V0LCBsZW5ndGgpIHtcblxuICBkbyB7XG5cbiAgICB2YXIgaSA9IDA7XG4gICAgdmFyIGxpbWl0ID0gKGxlbmd0aCA8IENvbnN0LkhBU0hfTEVOR1RIID8gbGVuZ3RoIDogQ29uc3QuSEFTSF9MRU5HVEgpO1xuXG4gICAgd2hpbGUgKGkgPCBsaW1pdCkge1xuXG4gICAgICB0aGlzLnN0YXRlW2krK10gPSB0cml0c1tvZmZzZXQrK107XG4gICAgfVxuXG4gICAgdGhpcy50cmFuc2Zvcm0oKTtcblxuICB9IHdoaWxlICgoIGxlbmd0aCAtPSBDb25zdC5IQVNIX0xFTkdUSCApID4gMClcblxufVxuXG4vKipcbiAqICAgU3BvbmdlIHNxdWVlemUgZnVuY3Rpb25cbiAqXG4gKiAgIEBtZXRob2Qgc3F1ZWV6ZVxuICoqL1xuQ3VybC5wcm90b3R5cGUuc3F1ZWV6ZSA9IGZ1bmN0aW9uKHRyaXRzLCBvZmZzZXQsIGxlbmd0aCkge1xuXG4gIGRvIHtcblxuICAgIHZhciBpID0gMDtcbiAgICB2YXIgbGltaXQgPSAobGVuZ3RoIDwgQ29uc3QuSEFTSF9MRU5HVEggPyBsZW5ndGggOiBDb25zdC5IQVNIX0xFTkdUSCk7XG5cbiAgICB3aGlsZSAoaSA8IGxpbWl0KSB7XG5cbiAgICAgIHRyaXRzW29mZnNldCsrXSA9IHRoaXMuc3RhdGVbaSsrXTtcbiAgICB9XG5cbiAgICB0aGlzLnRyYW5zZm9ybSgpO1xuXG4gIH0gd2hpbGUgKCggbGVuZ3RoIC09IENvbnN0LkhBU0hfTEVOR1RIICkgPiAwKVxufVxuXG4vKipcbiAqICAgU3BvbmdlIHRyYW5zZm9ybSBmdW5jdGlvblxuICpcbiAqICAgQG1ldGhvZCB0cmFuc2Zvcm1cbiAqKi9cbkN1cmwucHJvdG90eXBlLnRyYW5zZm9ybSA9IGZ1bmN0aW9uKCkge1xuXG4gIHZhciBzdGF0ZUNvcHkgPSBbXSwgaW5kZXggPSAwO1xuXG4gIGZvciAodmFyIHJvdW5kID0gMDsgcm91bmQgPCBDb25zdC5OVU1CRVJfT0ZfUk9VTkRTOyByb3VuZCsrKSB7XG5cbiAgICBzdGF0ZUNvcHkgPSB0aGlzLnN0YXRlLnNsaWNlKCk7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IENvbnN0LlNUQVRFX0xFTkdUSDsgaSsrKSB7XG5cbiAgICAgIHRoaXMuc3RhdGVbaV0gPSB0aGlzLnRydXRoVGFibGVbc3RhdGVDb3B5W2luZGV4XSArIChzdGF0ZUNvcHlbaW5kZXggKz0gKGluZGV4IDwgMzY1ID8gMzY0IDogLTM2NSldIDw8MikgKyA1XTtcbiAgICB9XG4gIH1cbn1cblxubW9kdWxlLmV4cG9ydHMgPSBDdXJsO1xuIiwiY29uc3QgUGVhcmxEaXZlciA9IHJlcXVpcmUoJy4vcGVhcmxkaXZlcicpO1xuY29uc3QgQ3VybCA9IHJlcXVpcmUoXCIuL2N1cmxcIik7XG5jb25zdCBDb25zdCA9IHJlcXVpcmUoJy4vY29uc3RhbnRzJyk7XG5jb25zdCBDb252ZXJ0ZXIgPSByZXF1aXJlKCdpb3RhLmNyeXB0by5qcycpLmNvbnZlcnRlcjtcbmNvbnN0IE5PTkNFX1RJTUVTVEFNUF9MT1dFUl9CT1VORCA9IDA7XG5jb25zdCBOT05DRV9USU1FU1RBTVBfVVBQRVJfQk9VTkQgPSBDb252ZXJ0ZXIuZnJvbVZhbHVlKDB4ZmZmZmZmZmZmZmZmZmZmZik7XG5jb25zdCBNQVhfVElNRVNUQU1QX1ZBTFVFID0gKE1hdGgucG93KDMsMjcpIC0gMSkgLyAyIFxuXG5sZXQgcGRJbnN0YW5jZTtcblxuY29uc3QgcG93ID0gKG9wdGlvbnMsIHN1Y2Nlc3MsIGVycm9yKSA9PiB7ICBcbiAgbGV0IHN0YXRlO1xuXG4gIGlmICgndHJ5dGVzJyBpbiBvcHRpb25zKSB7XG4gICAgc3RhdGUgPSBQZWFybERpdmVyLnByZXBhcmUob3B0aW9ucy50cnl0ZXMpO1xuICB9IGVsc2UgaWYgKCdzdGF0ZScgaW4gb3B0aW9ucykge1xuICAgIHN0YXRlID0gUGVhcmxEaXZlci5vZmZzZXRTdGF0ZShvcHRpb25zLnN0YXRlKTtcbiAgfSBlbHNlIHtcbiAgICBlcnJvcihcIkVycm9yOiBubyB0cnl0ZXMgb3Igc3RhdGUgbWF0cml4IHByb3ZpZGVkXCIpO1xuICB9XG4gIGxldCBwb3dQcm9taXNlID0gUGVhcmxEaXZlci5zZWFyY2gocGRJbnN0YW5jZSwgc3RhdGUsIG9wdGlvbnMubWluV2VpZ2h0KVxuICBpZih0eXBlb2Ygc3VjY2VzcyA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIHBvd1Byb21pc2UudGhlbihzdWNjZXNzKS5jYXRjaChlcnJvcilcbiAgfVxuICByZXR1cm4gcG93UHJvbWlzZTtcbn07XG5cbmNvbnN0IFRBR19UUklOQVJZX1NUQVJUID0gMjI5NTtcbmNvbnN0IFRBR19UUklOQVJZX1NJWkUgPSAyNztcblxuY29uc3Qgc2V0VGltZXN0YW1wID0gKHN0YXRlKSA9PiB7XG4gIGNvbnN0IHRpbWVzdGFtcCA9IHN0YXRlLnN1YmFycmF5KENvbnN0LlRJTUVTVEFNUF9TVEFSVCwgQ29uc3QuVElNRVNUQU1QX0xPV0VSX0JPVU5EX1NUQVJUKTtcbiAgY29uc3QgdXBwZXIgPSBzdGF0ZS5zdWJhcnJheShDb25zdC5USU1FU1RBTVBfVVBQRVJfQk9VTkRfU1RBUlQsIENvbnN0Lk5PTkNFX1NUQVJUKTtcbiAgdGltZXN0YW1wLmZpbGwoMCk7XG4gIENvbnZlcnRlci5mcm9tVmFsdWUoRGF0ZS5ub3coKSkubWFwKCh2LCBpKSA9PiB0aW1lc3RhbXBbaV0gPSB2KTtcbiAgc3RhdGUuc3ViYXJyYXkoQ29uc3QuVElNRVNUQU1QX0xPV0VSX0JPVU5EX1NUQVJULCBDb25zdC5USU1FU1RBTVBfVVBQRVJfQk9VTkRfU1RBUlQpLmZpbGwoMCk7XG4gIHVwcGVyLmZpbGwoMCk7XG4gIE5PTkNFX1RJTUVTVEFNUF9VUFBFUl9CT1VORC5tYXAoKHYsaSkgPT4gdXBwZXJbaV0gPSB2KTtcbn1cblxuY29uc3Qgb3ZlcnJpZGVBdHRhY2hUb1RhbmdsZSA9IGlvdGEgPT4ge1xuICBpb3RhLmFwaS5hdHRhY2hUb1RhbmdsZSA9IChcbiAgICB0cnVua1RyYW5zYWN0aW9uLFxuICAgIGJyYW5jaFRyYW5zYWN0aW9uLFxuICAgIG1pbldlaWdodCxcbiAgICB0cnl0ZXMsXG4gICAgY2FsbGJhY2tcbiAgKSA9PiB7XG4gIGNvbnN0IGNjdXJsSGFzaGluZyA9IGZ1bmN0aW9uKHRydW5rVHJhbnNhY3Rpb24sIGJyYW5jaFRyYW5zYWN0aW9uLCBtaW5XZWlnaHQsIHRyeXRlcywgY2FsbGJhY2spIHtcbiAgICBjb25zdCBpb3RhT2JqID0gaW90YVxuXG4gICAgLy8gaW5wdXRWYWxpZGF0b3I6IENoZWNrIGlmIGNvcnJlY3QgaGFzaFxuICAgIGlmICghaW90YU9iai52YWxpZC5pc0hhc2godHJ1bmtUcmFuc2FjdGlvbikpIHtcbiAgICAgIHJldHVybiBjYWxsYmFjayhuZXcgRXJyb3IoXCJJbnZhbGlkIHRydW5rVHJhbnNhY3Rpb25cIikpXG4gICAgfVxuXG4gICAgLy8gaW5wdXRWYWxpZGF0b3I6IENoZWNrIGlmIGNvcnJlY3QgaGFzaFxuICAgIGlmICghaW90YU9iai52YWxpZC5pc0hhc2goYnJhbmNoVHJhbnNhY3Rpb24pKSB7XG4gICAgICByZXR1cm4gY2FsbGJhY2sobmV3IEVycm9yKFwiSW52YWxpZCBicmFuY2hUcmFuc2FjdGlvblwiKSlcbiAgICB9XG5cbiAgICAvLyBpbnB1dFZhbGlkYXRvcjogQ2hlY2sgaWYgaW50XG4gICAgaWYgKCFpb3RhT2JqLnZhbGlkLmlzVmFsdWUobWluV2VpZ2h0KSkge1xuICAgICAgcmV0dXJuIGNhbGxiYWNrKG5ldyBFcnJvcihcIkludmFsaWQgbWluV2VpZ2h0TWFnbml0dWRlXCIpKVxuICAgIH1cblxuICAgIHZhciBmaW5hbEJ1bmRsZVRyeXRlcyA9IFtdXG4gICAgdmFyIHByZXZpb3VzVHhIYXNoXG4gICAgdmFyIGkgPSAwXG5cbiAgICBmdW5jdGlvbiBsb29wVHJ5dGVzKCkge1xuICAgICAgZ2V0QnVuZGxlVHJ5dGVzKHRyeXRlc1tpXSwgZnVuY3Rpb24oZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yKSB7XG4gICAgICAgICAgcmV0dXJuIGNhbGxiYWNrKGVycm9yKVxuICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgIGkrK1xuICAgICAgICAgIGlmIChpIDwgdHJ5dGVzLmxlbmd0aCkge1xuICAgICAgICAgICAgbG9vcFRyeXRlcygpXG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vIHJldmVyc2UgdGhlIG9yZGVyIHNvIHRoYXQgaXQncyBhc2NlbmRpbmcgZnJvbSBjdXJyZW50SW5kZXhcbiAgICAgICAgICAgIHJldHVybiBjYWxsYmFjayhudWxsLCBmaW5hbEJ1bmRsZVRyeXRlcy5yZXZlcnNlKCkpXG4gICAgICAgICAgfVxuICAgICAgICB9XG4gICAgICB9KVxuICAgIH1cblxuICAgIGZ1bmN0aW9uIGdldEJ1bmRsZVRyeXRlcyh0aGlzVHJ5dGVzLCBjYWxsYmFjaykge1xuICAgICAgLy8gUFJPQ0VTUyBMT0dJQzpcbiAgICAgIC8vIFN0YXJ0IHdpdGggbGFzdCBpbmRleCB0cmFuc2FjdGlvblxuICAgICAgLy8gQXNzaWduIGl0IHRoZSB0cnVuayAvIGJyYW5jaCB3aGljaCB0aGUgdXNlciBoYXMgc3VwcGxpZWRcbiAgICAgIC8vIElGIHRoZXJlIGlzIGEgYnVuZGxlLCBjaGFpbiAgdGhlIGJ1bmRsZSB0cmFuc2FjdGlvbnMgdmlhXG4gICAgICAvLyB0cnVua1RyYW5zYWN0aW9uIHRvZ2V0aGVyXG5cbiAgICAgIHZhciB0eE9iamVjdCA9IGlvdGFPYmoudXRpbHMudHJhbnNhY3Rpb25PYmplY3QodGhpc1RyeXRlcylcbiAgICAgIHR4T2JqZWN0LnRhZyA9IHR4T2JqZWN0Lm9ic29sZXRlVGFnXG4gICAgICB0eE9iamVjdC5hdHRhY2htZW50VGltZXN0YW1wID0gRGF0ZS5ub3coKVxuICAgICAgdHhPYmplY3QuYXR0YWNobWVudFRpbWVzdGFtcExvd2VyQm91bmQgPSAwXG4gICAgICB0eE9iamVjdC5hdHRhY2htZW50VGltZXN0YW1wVXBwZXJCb3VuZCA9IE1BWF9USU1FU1RBTVBfVkFMVUVcbiAgICAgIC8vIElmIHRoaXMgaXMgdGhlIGZpcnN0IHRyYW5zYWN0aW9uLCB0byBiZSBwcm9jZXNzZWRcbiAgICAgIC8vIE1ha2Ugc3VyZSB0aGF0IGl0J3MgdGhlIGxhc3QgaW4gdGhlIGJ1bmRsZSBhbmQgdGhlblxuICAgICAgLy8gYXNzaWduIGl0IHRoZSBzdXBwbGllZCB0cnVuayBhbmQgYnJhbmNoIHRyYW5zYWN0aW9uc1xuICAgICAgaWYgKCFwcmV2aW91c1R4SGFzaCkge1xuICAgICAgICAvLyBDaGVjayBpZiBsYXN0IHRyYW5zYWN0aW9uIGluIHRoZSBidW5kbGVcbiAgICAgICAgaWYgKHR4T2JqZWN0Lmxhc3RJbmRleCAhPT0gdHhPYmplY3QuY3VycmVudEluZGV4KSB7XG4gICAgICAgICAgcmV0dXJuIGNhbGxiYWNrKFxuICAgICAgICAgICAgbmV3IEVycm9yKFxuICAgICAgICAgICAgICBcIldyb25nIGJ1bmRsZSBvcmRlci4gVGhlIGJ1bmRsZSBzaG91bGQgYmUgb3JkZXJlZCBpbiBkZXNjZW5kaW5nIG9yZGVyIGZyb20gY3VycmVudEluZGV4XCJcbiAgICAgICAgICAgIClcbiAgICAgICAgICApXG4gICAgICAgIH1cblxuICAgICAgICB0eE9iamVjdC50cnVua1RyYW5zYWN0aW9uID0gdHJ1bmtUcmFuc2FjdGlvblxuICAgICAgICB0eE9iamVjdC5icmFuY2hUcmFuc2FjdGlvbiA9IGJyYW5jaFRyYW5zYWN0aW9uXG4gICAgICB9IGVsc2Uge1xuICAgICAgICAvLyBDaGFpbiB0aGUgYnVuZGxlIHRvZ2V0aGVyIHZpYSB0aGUgdHJ1bmtUcmFuc2FjdGlvbiAocHJldmlvdXMgdHggaW4gdGhlIGJ1bmRsZSlcbiAgICAgICAgLy8gQXNzaWduIHRoZSBzdXBwbGllZCB0cnVua1RyYW5zYWNpdG9uIGFzIGJyYW5jaFRyYW5zYWN0aW9uXG4gICAgICAgIHR4T2JqZWN0LnRydW5rVHJhbnNhY3Rpb24gPSBwcmV2aW91c1R4SGFzaFxuICAgICAgICB0eE9iamVjdC5icmFuY2hUcmFuc2FjdGlvbiA9IHRydW5rVHJhbnNhY3Rpb25cbiAgICAgIH1cblxuICAgICAgdmFyIG5ld1RyeXRlcyA9IGlvdGFPYmoudXRpbHMudHJhbnNhY3Rpb25Ucnl0ZXModHhPYmplY3QpXG5cbiAgICAgIGN1cmxcbiAgICAgICAgLnBvdyh7IHRyeXRlczogbmV3VHJ5dGVzLCBtaW5XZWlnaHQ6IG1pbldlaWdodCB9KVxuICAgICAgICAudGhlbihmdW5jdGlvbihub25jZSkge1xuICAgICAgICAgIHZhciByZXR1cm5lZFRyeXRlcyA9IG5ld1RyeXRlcy5zdWJzdHIoMCwgMjY3MyAtIDgxKS5jb25jYXQobm9uY2UpXG4gICAgICAgICAgdmFyIG5ld1R4T2JqZWN0ID0gaW90YU9iai51dGlscy50cmFuc2FjdGlvbk9iamVjdChyZXR1cm5lZFRyeXRlcylcblxuICAgICAgICAgIC8vIEFzc2lnbiB0aGUgcHJldmlvdXNUeEhhc2ggdG8gdGhpcyB0eFxuICAgICAgICAgIHZhciB0eEhhc2ggPSBuZXdUeE9iamVjdC5oYXNoXG4gICAgICAgICAgcHJldmlvdXNUeEhhc2ggPSB0eEhhc2hcblxuICAgICAgICAgIGZpbmFsQnVuZGxlVHJ5dGVzLnB1c2gocmV0dXJuZWRUcnl0ZXMpXG4gICAgICAgICAgY2FsbGJhY2sobnVsbClcbiAgICAgICAgfSlcbiAgICAgICAgLmNhdGNoKGNhbGxiYWNrKVxuICAgIH1cbiAgICBsb29wVHJ5dGVzKClcbiAgfVxuICBjY3VybEhhc2hpbmcodHJ1bmtUcmFuc2FjdGlvbiwgYnJhbmNoVHJhbnNhY3Rpb24sIG1pbldlaWdodCwgdHJ5dGVzLCBmdW5jdGlvbihlcnJvciwgc3VjY2Vzcykge1xuICAgIGlmIChlcnJvcikge1xuICAgICAgICBjb25zb2xlLmxvZyhlcnJvcik7XG4gICAgfSBlbHNlIHtcbiAgICAgICAgY29uc29sZS5sb2coc3VjY2Vzcyk7XG4gICAgfVxuICAgIGlmIChjYWxsYmFjaykge1xuICAgICAgICByZXR1cm4gY2FsbGJhY2soZXJyb3IsIHN1Y2Nlc3MpO1xuICAgIH0gZWxzZSB7XG4gICAgICAgIHJldHVybiBzdWNjZXNzO1xuICAgIH1cbiAgfSlcbiAgfVxufVxuXG53aW5kb3cuY3VybCA9IG1vZHVsZS5leHBvcnRzID0ge1xuICBpbml0OiAoKSA9PiB7IFxuICAgIHBkSW5zdGFuY2UgPSBQZWFybERpdmVyLmluc3RhbmNlKCk7IFxuICAgIGlmKHBkSW5zdGFuY2UgPT0gbnVsbCkge1xuICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cbiAgICByZXR1cm4gdHJ1ZTtcbiAgfSxcbiAgcG93LFxuICBwcmVwYXJlOiBQZWFybERpdmVyLnByZXBhcmUsXG4gIHNldE9mZnNldDogKG8pID0+IHtwZEluc3RhbmNlLm9mZnNldCA9IG99LFxuICBpbnRlcnJ1cHQ6ICgpID0+IGludGVycnVwdChwZEluc3RhbmNlKSxcbiAgcmVzdW1lOiAoKSA9PiBQZWFybERpdmVyLmRvTmV4dChwZEluc3RhbmNlKSxcbiAgcmVtb3ZlOiAoKSA9PiBwZEluc3RhbmNlLnF1ZXVlLnVuc2hpZnQoKSxcbiAgLy9nZXRIYXNoUm93czogKGMpID0+IGMoUGVhcmxEaXZlci5nZXRIYXNoQ291bnQoKSksXG4gIG92ZXJyaWRlQXR0YWNoVG9UYW5nbGVcbn1cbiIsImNvbnN0IENvbnZlcnRlciA9IHJlcXVpcmUoJ2lvdGEuY3J5cHRvLmpzJykuY29udmVydGVyO1xuY29uc3QgQ3VybCA9IHJlcXVpcmUoXCIuL2N1cmxcIik7XG5jb25zdCBXZWJHTCA9IHJlcXVpcmUoJy4vV2ViR0wnKTtcbmNvbnN0IFNlYXJjaEluaXQgPSByZXF1aXJlKCcuL3NlYXJjaEluaXQnKTtcbmNvbnN0IEtSTkwgPSByZXF1aXJlKCcuL3NoYWRlcnMnKTtcbmNvbnN0IENvbnN0ID0gcmVxdWlyZSgnLi9jb25zdGFudHMnKTtcblxuY29uc3QgVEVYRUxTSVpFID0gNDtcblxuY29uc3QgUERTdGF0ZSA9IHtcbiAgUkVBRFk6IDAsXG4gIFNFQVJDSElORzogMSxcbiAgSU5URVJSVVBURUQ6IC0xLFxufTtcblxuY29uc3QgcGFjayA9IChsKSA9PiAocixrLGkpID0+IChpJWwgPT09MCA/IHIucHVzaChba10pOiByW3IubGVuZ3RoLTFdLnB1c2goaykpICYmIHI7XG5cbmNvbnN0IHBlYXJsRGl2ZXJDYWxsYmFjayA9IChyZXMsIHRyYW5zYWN0aW9uVHJpdHMsIG1pbldlaWdodE1hZ25pdHVkZSwgbV9zZWxmKSA9PiBcbntcbiAgcmV0dXJuIChub25jZSwgc2VhcmNoT2JqZWN0KSA9PiB7XG4gICAgcmVzKENvbnZlcnRlci50cnl0ZXMobm9uY2UpKTtcbiAgfVxufVxuXG5jb25zdCBQZWFybERpdmVySW5zdGFuY2UgPSAob2Zmc2V0KSA9PiB7XG4gIGlmKFdlYkdMKSB7XG4gICAgbGV0IGluc3RhbmNlID0gbmV3IE9iamVjdCgpO1xuICAgIGluc3RhbmNlLmNvbnRleHQgPSBXZWJHTC53b3JrZXIoQ29uc3QuU1RBVEVfTEVOR1RIKzEsIFRFWEVMU0laRSk7XG4gICAgaW5zdGFuY2Uub2Zmc2V0ID0gaW5zdGFuY2UuY29udGV4dC5kaW0ueSAqIChvZmZzZXQgfHwgMCk7XG4gICAgaW5zdGFuY2UuYnVmID0gaW5zdGFuY2UuY29udGV4dC5pcHQuZGF0YTtcbiAgICBXZWJHTC5hZGRQcm9ncmFtKGluc3RhbmNlLmNvbnRleHQsIFwiaW5pdFwiLCBLUk5MLmluaXQsIFwiZ3Jfb2Zmc2V0XCIpO1xuICAgIFdlYkdMLmFkZFByb2dyYW0oaW5zdGFuY2UuY29udGV4dCwgXCJpbmNyZW1lbnRcIiwgS1JOTC5pbmNyZW1lbnQpO1xuICAgIFdlYkdMLmFkZFByb2dyYW0oaW5zdGFuY2UuY29udGV4dCwgXCJ0d2lzdFwiLCBLUk5MLnRyYW5zZm9ybSk7XG4gICAgV2ViR0wuYWRkUHJvZ3JhbShpbnN0YW5jZS5jb250ZXh0LCBcImNoZWNrXCIsIEtSTkwuY2hlY2ssIFwibWluV2VpZ2h0TWFnbml0dWRlXCIpO1xuICAgIFdlYkdMLmFkZFByb2dyYW0oaW5zdGFuY2UuY29udGV4dCwgXCJjb2xfY2hlY2tcIiwgS1JOTC5jb2xfY2hlY2spO1xuICAgIFdlYkdMLmFkZFByb2dyYW0oaW5zdGFuY2UuY29udGV4dCwgXCJmaW5hbGl6ZVwiLCBLUk5MLmZpbmFsaXplKTtcbiAgICBpbnN0YW5jZS5zdGF0ZSA9IFBEU3RhdGUuUkVBRFk7XG4gICAgaW5zdGFuY2UucXVldWUgPSBbXTtcbiAgICByZXR1cm4gaW5zdGFuY2U7XG4gIH1cbn1cblxuY29uc3Qgc2VhcmNoID0gKGluc3RhbmNlLCBzdGF0ZXMsIG1pbldlaWdodCkgPT57XG4gIGlmKCFpbnN0YW5jZS5jb250ZXh0KSB7XG4gICAgUHJvbWlzZS5yZWplY3QobmV3IEVycm9yKFwiV2ViZ2wyIElzIG5vdCBBdmFpbGFibGVcIikpO1xuICB9IGVsc2UgaWYgKG1pbldlaWdodCA+PSBDb25zdC5IQVNIX0xFTkdUSCB8fCBtaW5XZWlnaHQgPD0gMCkge1xuICAgIFByb21pc2UucmVqZWN0KG5ldyBFcnJvcihcIkJhZCBNaW4tV2VpZ2h0IE1hZ25pdHVkZVwiKSk7XG4gIH1cbiAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXMsIHJlaikgPT4ge1xuICAgIGluc3RhbmNlLnF1ZXVlLnB1c2goe1xuICAgICAgc3RhdGVzOiBzdGF0ZXMsIFxuICAgICAgbXdtOiBtaW5XZWlnaHQsIFxuICAgICAgY2FsbDogcGVhcmxEaXZlckNhbGxiYWNrKHJlcywgc3RhdGVzLCBtaW5XZWlnaHQsIGluc3RhbmNlKVxuICAgIH0pO1xuICAgIGlmKGluc3RhbmNlLnN0YXRlID09IFBEU3RhdGUuUkVBRFkpIGRvTmV4dChpbnN0YW5jZSk7XG4gIH0pO1xufVxuXG5jb25zdCBpbnRlcnJ1cHQgPSAoaW5zdGFuY2UpID0+IHtcbiAgaWYoaW5zdGFuY2Uuc3RhdGUgPT0gUERTdGF0ZS5TRUFSQ0hJTkcpIGluc3RhbmNlLnN0YXRlID0gUERTdGF0ZS5JTlRFUlJVUFRFRDtcbn1cblxuY29uc3QgZG9OZXh0ID0gKGluc3RhbmNlKSA9PiB7XG4gIHZhciBuZXh0ID0gaW5zdGFuY2UucXVldWUuc2hpZnQoKTtcbiAgaWYoaW5zdGFuY2Uuc3RhdGUgIT0gUERTdGF0ZS5TRUFSQ0hJTkcpIHtcbiAgICBpZihuZXh0ICE9IG51bGwpIHtcbiAgICAgIGluc3RhbmNlLnN0YXRlID0gUERTdGF0ZS5TRUFSQ0hJTkc7XG4gICAgICBfV2ViR0xGaW5kTm9uY2UoaW5zdGFuY2UsIG5leHQpO1xuICAgIH0gXG4gIH0gZWxzZSB7XG4gICAgaW5zdGFuY2Uuc3RhdGUgPSBQRFN0YXRlLlJFQURZO1xuICB9XG59XG5cbmNvbnN0IF9zYXZlID0gKGluc3RhbmNlLCBzZWFyY2hPYmplY3QpID0+IHtcbiAgaW5zdGFuY2UuYnVmLnJlZHVjZShwYWNrKDQpLCBbXSkuc2xpY2UoMCxDb25zdC5TVEFURV9MRU5HVEgpXG4gICAgLnJlZHVjZSgoYSx2KT0+IGEubWFwKChjLGkpID0+IGMucHVzaCh2W2ldKSkmJiBhLCBbW10sW11dKVxuICAgIC5yZWR1Y2UoKGEsdixpKSA9PiAoaSUyID8gYS5zZXQoXCJoaWdoXCIsIHYpIDogYS5zZXQoXCJsb3dcIiwgdikpICYmIGEsIG5ldyBNYXAoKSlcbiAgICAuZm9yRWFjaCgodixrKSA9PiBzZWFyY2hPYmplY3Quc3RhdGVzW2tdID0gdik7XG4gIGluc3RhbmNlLnF1ZXVlLnVuc2hpZnQoc2VhcmNoT2JqZWN0KTtcbn1cblxuY29uc3QgX1dlYkdMV3JpdGVCdWZmZXJzID0gKGluc3RhbmNlLCBzdGF0ZXMpID0+IHtcbiAgZm9yKHZhciBpID0gMDsgaSA8IENvbnN0LlNUQVRFX0xFTkdUSDsgaSsrKSB7XG4gICAgaW5zdGFuY2UuYnVmW2kgKiBURVhFTFNJWkVdID0gc3RhdGVzLmxvd1tpXTtcbiAgICBpbnN0YW5jZS5idWZbaSAqIFRFWEVMU0laRSArIDFdID0gc3RhdGVzLmhpZ2hbaV07XG4gICAgaW5zdGFuY2UuYnVmW2kgKiBURVhFTFNJWkUgKyAyXSA9IHN0YXRlcy5sb3dbaV07XG4gICAgaW5zdGFuY2UuYnVmW2kgKiBURVhFTFNJWkUgKyAzXSA9IHN0YXRlcy5oaWdoW2ldO1xuICB9XG59XG5cblxuY29uc3QgX1dlYkdMU2VhcmNoID0gKGluc3RhbmNlLCBzZWFyY2hPYmplY3QpID0+IHtcbiAgV2ViR0wucnVuKGluc3RhbmNlLmNvbnRleHQsIFwiaW5jcmVtZW50XCIpO1xuICBXZWJHTC5ydW4oaW5zdGFuY2UuY29udGV4dCwgXCJ0d2lzdFwiLCBDb25zdC5OVU1CRVJfT0ZfUk9VTkRTKTtcbiAgV2ViR0wucnVuKGluc3RhbmNlLmNvbnRleHQsIFwiY2hlY2tcIiwgMSwge246XCJtaW5XZWlnaHRNYWduaXR1ZGVcIiwgdjogc2VhcmNoT2JqZWN0Lm13bX0pO1xuICBXZWJHTC5ydW4oaW5zdGFuY2UuY29udGV4dCwgXCJjb2xfY2hlY2tcIik7XG5cbiAgaWYoV2ViR0wucmVhZERhdGEoaW5zdGFuY2UuY29udGV4dCwgQ29uc3QuU1RBVEVfTEVOR1RILDAsIDEsIDEpWzJdID09PSAtMSApIHtcbiAgICBpZihpbnN0YW5jZS5zdGF0ZSA9PSBQRFN0YXRlLklOVEVSUlVQVEVEKSByZXR1cm4gaW5zdGFuY2UuX3NhdmUoc2VhcmNoT2JqZWN0KTtcbiAgICAvL3JlcXVlc3RBbmltYXRpb25GcmFtZSgoKSA9PiBpbnN0YW5jZS5fV2ViR0xTZWFyY2goc2VhcmNoT2JqZWN0KSk7XG4gICAgc2V0VGltZW91dCgoKSA9PiBfV2ViR0xTZWFyY2goaW5zdGFuY2UsIHNlYXJjaE9iamVjdCksIDEpO1xuICB9IGVsc2Uge1xuICAgIFdlYkdMLnJ1bihpbnN0YW5jZS5jb250ZXh0LCBcImZpbmFsaXplXCIpO1xuICAgIHNlYXJjaE9iamVjdC5jYWxsKFxuICAgICAgV2ViR0wucmVhZERhdGEoaW5zdGFuY2UuY29udGV4dCwgMCwwLGluc3RhbmNlLmNvbnRleHQuZGltLngsMSlcbiAgICAgIC5yZWR1Y2UocGFjayg0KSwgW10pXG4gICAgICAuc2xpY2UoMCwgQ29uc3QuSEFTSF9MRU5HVEgpXG4gICAgICAubWFwKHggPT4geFszXSksIFxuICAgICAgc2VhcmNoT2JqZWN0KTtcbiAgICBkb05leHQoaW5zdGFuY2UpO1xuICB9XG59XG5cbmNvbnN0IF9XZWJHTEZpbmROb25jZSA9IChpbnN0YW5jZSwgc2VhcmNoT2JqZWN0KSA9PiB7XG4gIF9XZWJHTFdyaXRlQnVmZmVycyhpbnN0YW5jZSwgc2VhcmNoT2JqZWN0LnN0YXRlcyk7XG4gIFdlYkdMLndyaXRlRGF0YShpbnN0YW5jZS5jb250ZXh0LCBpbnN0YW5jZS5idWYpO1xuICBXZWJHTC5ydW4oaW5zdGFuY2UuY29udGV4dCwgXCJpbml0XCIsIDEsIHtuOiBcImdyX29mZnNldFwiLCB2OiBpbnN0YW5jZS5vZmZzZXR9KTtcbiAgLy9yZXF1ZXN0QW5pbWF0aW9uRnJhbWUoKCkgPT4gaW5zdGFuY2UuX1dlYkdMU2VhcmNoKHNlYXJjaE9iamVjdCkpO1xuICBzZXRUaW1lb3V0KCgpID0+IF9XZWJHTFNlYXJjaChpbnN0YW5jZSwgc2VhcmNoT2JqZWN0KSwgMSk7XG59XG5jb25zdCBzZWFyY2hXaXRoQ2FsbGJhY2sgPSAoaW5zdGFuY2UsIHRyYW5zYWN0aW9uVHJ5dGVzLCBtaW5XZWlnaHRNYWduaXR1ZGUsIGNhbGxiYWNrLCBlcnIpID0+IHtcbiAgaWYgKHRyYW5zYWN0aW9uVHJpdHMubGVuZ3RoIDwgQ29uc3QuVFJBTlNBQ1RJT05fTEVOR1RIIC0gQ29uc3QuSEFTSF9MRU5HVEgpIHJldHVybiBudWxsO1xuICB2YXIgY3VybCA9IG5ldyBDdXJsKCk7XG4gIGxldCB0cmFuc2FjdGlvblRyaXRzID0gQ29udmVydGVyLnRyaXRzKHRyYW5zYWN0aW9uVHJ5dGVzKTtcbiAgY3VybC5hYnNvcmIodHJhbnNhY3Rpb25Ucml0cywgMCwgQ29uc3QuVFJBTlNBQ1RJT05fTEVOR1RIIC0gQ29uc3QuSEFTSF9MRU5HVEgpO1xuICBjb25zdCBzdGF0ZXMgPSBTZWFyY2hJbml0LnRvUGFpcihjdXJsLnN0YXRlLCBtaW5XZWlnaHRNYWduaXR1ZGUpO1xuICBzZWFyY2goaW5zdGFuY2UsIHN0YXRlcywgbWluV2VpZ2h0TWFnbml0dWRlKS50aGVuKGNhbGxiYWNrKS5jYXRjaChlcnIpO1xufVxuY29uc3Qgb2Zmc2V0U3RhdGUgPSAoc3RhdGUpID0+IHtcbiAgICByZXR1cm4gU2VhcmNoSW5pdC50b1BhaXIoQ29udmVydGVyLnRyaXRzKHN0YXRlKSk7XG59XG5jb25zdCBwcmVwYXJlID0gKHRyYW5zYWN0aW9uVHJ5dGVzLCBtaW5XZWlnaHRNYWduaXR1ZGUpID0+IHtcbiAgdmFyIGN1cmwgPSBuZXcgQ3VybCgpO1xuICBsZXQgdHJhbnNhY3Rpb25Ucml0cyA9IENvbnZlcnRlci50cml0cyh0cmFuc2FjdGlvblRyeXRlcyk7XG4gIGN1cmwuYWJzb3JiKHRyYW5zYWN0aW9uVHJpdHMsIDAsIENvbnN0LlRSQU5TQUNUSU9OX0xFTkdUSCAtIENvbnN0LkhBU0hfTEVOR1RIKTtcbiAgdHJhbnNhY3Rpb25Ucml0cy5zbGljZShDb25zdC5UUkFOU0FDVElPTl9MRU5HVEggLSBDb25zdC5IQVNIX0xFTkdUSCwgQ29uc3QuVFJBTlNBQ1RJT05fTEVOR1RIKS5mb3JFYWNoKCh2LGkpID0+IHsgY3VybC5zdGF0ZVtpXSA9IHY7IH0pO1xuICBjb25zdCBzdGF0ZXMgPSBTZWFyY2hJbml0LnRvUGFpcihjdXJsLnN0YXRlKTtcbiAgcmV0dXJuIHN0YXRlcztcbn1cblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gIGluc3RhbmNlOiBQZWFybERpdmVySW5zdGFuY2UsXG4gIG9mZnNldFN0YXRlLFxuICBwcmVwYXJlLFxuICBzZWFyY2gsXG4gIGRvTmV4dCxcbn07XG4iLCJjb25zdCBDb25zdCA9IHJlcXVpcmUoJy4vY29uc3RhbnRzJylcbmxldCBcbiAgVFJZVEVfTEVOR1RIID0gMjY3MyxcbiAgVFJBTlNBQ1RJT05fTEVOR1RIPSBUUllURV9MRU5HVEggKiAzLFxuICBMT1dfQklUUz0gMCwvLzAwMDAwMDAwLFxuICBISUdIX0JJVFM9IC0xLC8vMHhGRkZGRkZGRiwvL0ZGRkZGRkZGLDQyOTQ5NjcyOTUsIFxuICBMT1dfMD0gMHhEQjZEQjZEQiwvLzZEQjZEQjZELFxuICBMT1dfMT0gMHhGMUY4RkM3RSwvLzNGMUY4RkM3LFxuICBMT1dfMj0gMHg3RkZGRTAwRiwvL0ZGRkMwMUZGLFxuICBMT1dfMz0gMHhGRkMwMDAwMCwvLzA3RkZGRkZGLFxuICBISUdIXzA9IDB4QjZEQjZEQjYsLy9EQjZEQjZEQixcbiAgSElHSF8xPSAweDhGQzdFM0YxLC8vRjhGQzdFM0YsXG4gIEhJR0hfMj0gMHhGRkMwMUZGRiwvL0Y4MDNGRkZGLFxuICBISUdIXzM9IDB4MDAzRkZGRkY7IC8vRkZGRkZGRkYsXG4vKlxuICBISUdIX0JJVFM9IDB4RkZGRkZGRkZGRkZGRkZGRixcbiAgTE9XX0JJVFM9IDB4MDAwMDAwMDAwMDAwMDAwMCxcbiAgTE9XXzA9IDB4REI2REI2REI2REI2REI2RCxcbiAgSElHSF8wPSAweEI2REI2REI2REI2REI2REIsXG4gIExPV18xPSAweEYxRjhGQzdFM0YxRjhGQzcsXG4gIEhJR0hfMT0gMHg4RkM3RTNGMUY4RkM3RTNGLFxuICBMT1dfMj0gMHg3RkZGRTAwRkZGRkMwMUZGLFxuICBISUdIXzI9IDB4RkZDMDFGRkZGODAzRkZGRixcbiAgTE9XXzM9IDB4RkZDMDAwMDAwN0ZGRkZGRixcbiAgSElHSF8zPSAweDAwM0ZGRkZGRkZGRkZGRkY7XG4gICovXG5cblxuZnVuY3Rpb24gb2Zmc2V0KHN0YXRlcywgb2Zmc2V0KSB7XG4gIHN0YXRlcy5sb3cgW29mZnNldCArIDBdID0gTE9XXzA7XG4gIHN0YXRlcy5sb3cgW29mZnNldCArIDFdID0gTE9XXzE7XG4gIHN0YXRlcy5sb3cgW29mZnNldCArIDJdID0gTE9XXzI7XG4gIHN0YXRlcy5sb3cgW29mZnNldCArIDNdID0gTE9XXzM7XG4gIHN0YXRlcy5oaWdoW29mZnNldCArIDBdID0gSElHSF8wO1xuICBzdGF0ZXMuaGlnaFtvZmZzZXQgKyAxXSA9IEhJR0hfMTtcbiAgc3RhdGVzLmhpZ2hbb2Zmc2V0ICsgMl0gPSBISUdIXzI7XG4gIHN0YXRlcy5oaWdoW29mZnNldCArIDNdID0gSElHSF8zO1xufVxuXG5mdW5jdGlvbiB0b1BhaXIoc3RhdGUpIHtcbiAgY29uc3Qgc3RhdGVzID0ge1xuICAgIGxvdyA6IG5ldyBJbnQzMkFycmF5KENvbnN0LlNUQVRFX0xFTkdUSCksXG4gICAgaGlnaCA6IG5ldyBJbnQzMkFycmF5KENvbnN0LlNUQVRFX0xFTkdUSClcbiAgfVxuICBzdGF0ZS5mb3JFYWNoKCh0cml0LCBpKSA9PiB7XG4gICAgc3dpdGNoICh0cml0KSB7XG4gICAgICBjYXNlIDA6IHtcbiAgICAgICAgc3RhdGVzLmxvd1tpXSA9IEhJR0hfQklUUztcbiAgICAgICAgc3RhdGVzLmhpZ2hbaV0gPSBISUdIX0JJVFM7XG4gICAgICB9IGJyZWFrO1xuICAgICAgY2FzZSAxOiB7XG4gICAgICAgIHN0YXRlcy5sb3dbaV0gPSBMT1dfQklUUztcbiAgICAgICAgc3RhdGVzLmhpZ2hbaV0gPSBISUdIX0JJVFM7XG4gICAgICB9IGJyZWFrO1xuICAgICAgZGVmYXVsdDoge1xuICAgICAgICBzdGF0ZXMubG93W2ldID0gSElHSF9CSVRTO1xuICAgICAgICBzdGF0ZXMuaGlnaFtpXSA9IExPV19CSVRTO1xuICAgICAgfVxuICAgIH1cbiAgfSk7XG4gIG9mZnNldChzdGF0ZXMsIENvbnN0Lk5PTkNFX1NUQVJUKTtcbiAgcmV0dXJuIHN0YXRlcztcbn1cblxuZnVuY3Rpb24gdHJhbnNmb3JtKHN0YXRlcykge1xuICB2YXIgc2NyYXRjaHBhZEhpZ2gsIHNjcmF0Y2hwYWRMb3dcbiAgdmFyIHNjcmF0Y2hwYWRJbmRleCA9IDAsIHJvdW5kLCBzdGF0ZUluZGV4O1xuICB2YXIgYWxwaGEsIGJldGEsIGdhbW1hLCBkZWx0YTtcblxuICBmb3IgKHJvdW5kID0gQ29uc3QuTlVNQkVSX09GX1JPVU5EUzsgcm91bmQtLSA+IDA7ICkge1xuICAgIHNjcmF0Y2hwYWRMb3cgPSBzdGF0ZXMubG93LnNsaWNlKCk7XG4gICAgc2NyYXRjaHBhZEhpZ2ggPSBzdGF0ZXMuaGlnaC5zbGljZSgpO1xuXG4gICAgZm9yIChzdGF0ZUluZGV4ID0gMDsgc3RhdGVJbmRleCA8IENvbnN0LlNUQVRFX0xFTkdUSDsgc3RhdGVJbmRleCsrKSB7XG4gICAgICBhbHBoYSA9IHNjcmF0Y2hwYWRMb3dbc2NyYXRjaHBhZEluZGV4XTtcbiAgICAgIGJldGEgPSBzY3JhdGNocGFkSGlnaFtzY3JhdGNocGFkSW5kZXhdO1xuICAgICAgZ2FtbWEgPSBzY3JhdGNocGFkSGlnaFtzY3JhdGNocGFkSW5kZXggKz0gKHNjcmF0Y2hwYWRJbmRleCA8IDM2NSA/IDM2NCA6IC0zNjUpXTtcbiAgICAgIGRlbHRhID0gKGFscGhhIHwgKH5nYW1tYSkpICYgKHNjcmF0Y2hwYWRMb3dbc2NyYXRjaHBhZEluZGV4XSBeIGJldGEpO1xuXG4gICAgICBzdGF0ZXMubG93W3N0YXRlSW5kZXhdID0gfmRlbHRhO1xuICAgICAgc3RhdGVzLmhpZ2hbc3RhdGVJbmRleF0gPSAoYWxwaGEgXiBnYW1tYSkgfCBkZWx0YTtcbiAgICB9XG4gIH1cbn1cblxubW9kdWxlLmV4cG9ydHMgPSB7IHRvUGFpciwgdHJhbnNmb3JtIH07XG4vKlxuZXhwb3J0IGRlZmF1bHQgZnVuY3Rpb24gKHN0YXRlcywgdHJhbnNhY3Rpb25Ucml0cykge1xuICB2YXIgaSwgb2Zmc2V0ID0gMDtcbiAgdmFyIGo7XG4gIC8vZm9yIChpID0gSEFTSF9MRU5HVEg7IGkgPCBTVEFURV9MRU5HVEg7IGkrKykge1xuICBmb3IgKGkgPSAwOyBpIDwgQ29uc3QuU1RBVEVfTEVOR1RIOyBpKyspIHtcbiAgICBpZiAoaSA+PSBDb25zdC5IQVNIX0xFTkdUSCAmJiBpIDwgQ29uc3QuU1RBVEVfTEVOR1RIKSB7XG4gICAgICBzdGF0ZXMubG93W2ldID0gSElHSF9CSVRTO1xuICAgICAgc3RhdGVzLmhpZ2hbaV0gPSBISUdIX0JJVFM7XG4gICAgfSBlbHNlIHtcbiAgICAgIHN0YXRlcy5sb3dbaV0gPSAwO1xuICAgICAgc3RhdGVzLmhpZ2hbaV0gPSAwO1xuICAgIH1cbiAgfVxuXG4gIGZvciAoaSA9IChDb25zdC5UUkFOU0FDVElPTl9MRU5HVEggLSBDb25zdC5IQVNIX0xFTkdUSCkgLyBDb25zdC5IQVNIX0xFTkdUSDsgaS0tID4gMDsgKSB7XG5cbiAgICBmb3IgKGogPSAwOyBqIDwgQ29uc3QuSEFTSF9MRU5HVEg7IGorKykge1xuICAgICAgc3dpdGNoICh0cmFuc2FjdGlvblRyaXRzW29mZnNldCsrXSkge1xuICAgICAgICBjYXNlIDA6IHtcbiAgICAgICAgICBzdGF0ZXMubG93W2pdID0gSElHSF9CSVRTO1xuICAgICAgICAgIHN0YXRlcy5oaWdoW2pdID0gSElHSF9CSVRTO1xuICAgICAgICB9IGJyZWFrO1xuICAgICAgICBjYXNlIDE6IHtcbiAgICAgICAgICBzdGF0ZXMubG93W2pdID0gTE9XX0JJVFM7XG4gICAgICAgICAgc3RhdGVzLmhpZ2hbal0gPSBISUdIX0JJVFM7XG4gICAgICAgIH0gYnJlYWs7XG4gICAgICAgIGRlZmF1bHQ6IHtcbiAgICAgICAgICBzdGF0ZXMubG93W2pdID0gSElHSF9CSVRTO1xuICAgICAgICAgIHN0YXRlcy5oaWdoW2pdID0gTE9XX0JJVFM7XG4gICAgICAgIH1cbiAgICAgIH1cbiAgICB9XG4gICAgdHJhbnNmb3JtKHN0YXRlcyk7XG4gIH1cbiAgc3RhdGVzLmxvd1swXSA9IExPV18wOyAgIC8vMGIxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxTDsgXG4gIHN0YXRlcy5oaWdoWzBdID0gSElHSF8wOyAvLzBiMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMTAxMUw7XG4gIHN0YXRlcy5sb3dbMV0gPSBMT1dfMTsgICAvLzBiMTExMTAwMDExMTExMTAwMDExMTExMTAwMDExMTExMTAwMDExMTExMTAwMDExMTExMTAwMDExMTExMTAwMDExMUw7IFxuICBzdGF0ZXMuaGlnaFsxXSA9IEhJR0hfMTsgLy8wYjEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTExMTFMO1xuICBzdGF0ZXMubG93WzJdID0gTE9XXzI7ICAgLy8wYjAxMTExMTExMTExMTExMTExMTEwMDAwMDAwMDAxMTExMTExMTExMTExMTExMTEwMDAwMDAwMDAxMTExMTExMTFMOyBcbiAgc3RhdGVzLmhpZ2hbMl0gPSBISUdIXzI7IC8vMGIxMTExMTExMTExMDAwMDAwMDAwMTExMTExMTExMTExMTExMTExMDAwMDAwMDAwMTExMTExMTExMTExMTExMTExTDtcbiAgc3RhdGVzLmxvd1szXSA9IExPV18zOyAgIC8vMGIxMTExMTExMTExMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTExMTExMTExMTExMTExMTExMTExMTExMTExTDsgXG4gIHN0YXRlcy5oaWdoWzNdID0gSElHSF8zOyAvLzBiMDAwMDAwMDAwMDExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMUw7XG59XG4qL1xuIiwibW9kdWxlLmV4cG9ydHMgPSBgXG5pbnQgc3VtIChpbnQgYSwgaW50IGIpIHtcbiAgaW50IG15X3N1bSA9IGEgKyBiO1xuICByZXR1cm4gbXlfc3VtID09IDIgPyAtMSA6IChteV9zdW0gPT0gLTIpID8gMSA6IG15X3N1bTtcbn1cbmludCBjb25zIChpbnQgYSwgaW50IGIpIHtcbiAgcmV0dXJuIChhID09IDEgJiYgYiA9PSAxKT8gMSA6IChhID09IC0xICYmIGIgPT0gLTEpID8gLTEgOiAwO1xufVxuaW50IGFueV90IChpbnQgYSwgaW50IGIpIHtcbiAgaW50IG15X2FueSA9IGEgKyBiO1xuICByZXR1cm4gbXlfYW55ID09IDAgPyAwIDogKG15X2FueSA+IDApID8gMSA6IC0xO1xufVxuaXZlYzIgZnVsbF9hZGRlcihpbnQgYSwgaW50IGIsIGludCBjKSB7XG4gIGludCBjX2EsIGNfYiwgc3VtX2FiLCBjX3M7XG5cbiAgY19hICAgID0gY29ucyhhLGIpO1xuICBzdW1fYWIgPSBzdW0oYSxiKTtcbiAgY19iICAgID0gY29ucyhzdW1fYWIsYyk7XG4gIGNfcyAgICA9IGFueV90KGNfYSwgY19iKTtcblxuICByZXR1cm4gaXZlYzIoc3VtKHN1bV9hYiwgYyksIGNfcyk7XG59XG5pdmVjMiBnZXRfc3VtX3RvX2luZGV4KGludCBmcm9tLCBpbnQgdG8sIGludCBudW1iZXJfdG9fYWRkLCBpbnQgcm93KSB7XG4gIGludCB0cml0X3RvX2FkZCwgdHJpdF9hdF9pbmRleCwgcG93LCBjYXJyeSwgbnVtX2NhcnJ5O1xuICBpdmVjMiByZWFkX2luLCBzdW1fb3V0LCBvdXRfdHJpdDtcbiAgcG93ID0gMTtcbiAgY2FycnkgPSAwO1xuICBudW1fY2FycnkgPSAwO1xuXG4gIGZvcihpbnQgaSA9IGZyb207IGkgPCB0bzsgaSsrKSB7XG4gICAgLy9pZih0cml0X3RvX2FkZCA9PSAwICYmIHN1bV9vdXQudCA9PSAwKSBjb250aW51ZTtcblxuICAgIHJlYWRfaW4gPSByZWFkX2F0ICggaXZlYzIgKGksIHJvdykpLnJnO1xuXG4gICAgdHJpdF90b19hZGQgPSAoKG51bWJlcl90b19hZGQgLyBwb3cpICUgMykgKyBudW1fY2Fycnk7XG4gICAgbnVtX2NhcnJ5ID0gdHJpdF90b19hZGQgPiAxID8gMSA6IDA7XG4gICAgdHJpdF90b19hZGQgPSAodHJpdF90b19hZGQgPT0gMiA/IC0xIDogKHRyaXRfdG9fYWRkID09IDMgPyAwIDogdHJpdF90b19hZGQpKTtcblxuICAgIHN1bV9vdXQgPSBmdWxsX2FkZGVyKFxuICAgICAgKHJlYWRfaW4ucyA9PSBMT1dfQklUUyA/IDEgOiByZWFkX2luLnQgPT0gTE9XX0JJVFM/IC0xIDogMCksIFxuICAgICAgdHJpdF90b19hZGQsIFxuICAgICAgY2FycnlcbiAgICApO1xuXG4gICAgaWYobXlfY29vcmQueCA9PSBpKSBicmVhaztcbiAgICBjYXJyeSA9IHN1bV9vdXQudDtcbiAgICBwb3cgKj0zO1xuICB9XG4gIGlmKHN1bV9vdXQucyA9PSAwKSB7XG4gICAgcmV0dXJuIGl2ZWMyKEhJR0hfQklUUyk7XG4gIH0gZWxzZSBpZiAoc3VtX291dC5zID09IDEpIHtcbiAgICByZXR1cm4gaXZlYzIoTE9XX0JJVFMsIEhJR0hfQklUUyk7XG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIGl2ZWMyKEhJR0hfQklUUywgTE9XX0JJVFMpO1xuICB9XG59XG5gXG4iLCJtb2R1bGUuZXhwb3J0cyA9IGBcbi8vIENob29zZSBoaWdoICE9IDAgaWYgeW91IHdhbnQgdG8gYmFycmllciByZyB2YWx1ZXMsIDAgaWYgeW91IHdhbnQgdG8gYmFycmllciBiYVxuI2RlZmluZSBXQUlUTlVNIDJcbnZvaWQgYmFycmllcihpdmVjMiB3YXRjaF9jb29yZHMsIGludCBoaWdoKSB7XG4gIGl2ZWM0IG15X3ZlYyA9IHJlYWQoKTtcbiAgaWYod2F0Y2hfY29vcmRzID09IG15X2Nvb3JkKSB7XG4gICAgaW50IGhvbGRfaW5kZXggPSAwO1xuICAgIGl2ZWM0IGhvbGRfdGV4ZWw7XG4gICAgbXlfdmVjLmcgPSBteV92ZWMuYSArIDE7XG4gICAgbXlfdmVjLmIgPSBteV92ZWMuZyArIDE7XG4gICAgY29tbWl0KG15X3ZlYyk7XG4gICAgd2hpbGUoaG9sZF9pbmRleCA8IFNUQVRFX0xFTkdUSCkge1xuICAgICAgaG9sZF90ZXhlbCA9IHJlYWRfYXQoaXZlYzIoaG9sZF9pbmRleCwgbXlfY29vcmQueSkpO1xuICAgICAgaWYoKGhpZ2ggPT0gMCAmJiBob2xkX3RleGVsLnIgPT0gV0FJVE5VTSkgfHwoaGlnaCAhPSAwICYmIGhvbGRfdGV4ZWwuYSA9PSBXQUlUTlVNKSlcbiAgICAgICAgaG9sZF9pbmRleCsrO1xuICAgIH1cbiAgICBteV92ZWMuYSA9IG15X3ZlYy5nO1xuICAgIC8vbXlfdmVjLmEgPSAxMjM7XG4gIH0gZWxzZSB7XG4gICAgaXZlYzQgd2F0Y2ggPSByZWFkX2F0KHdhdGNoX2Nvb3Jkcyk7IC8vIHI6IHZhbCB0byB3YXRjaCwgZzogZXhwZWN0ZWQgdmFsLCBiOiBuZXh0IHZhbCAoc2hvdWxkIGJlIDErIGV4cGVjdGVkIHZhbClcbiAgICBpbnQgaG9sZCA9IGhpZ2ggPT0gMCA/IG15X3ZlYy5yIDogbXlfdmVjLmE7XG4gICAgaWYoaGlnaCA9PSAwKVxuICAgICAgbXlfdmVjLnIgPSBXQUlUTlVNO1xuICAgIGVsc2VcbiAgICAgIG15X3ZlYy5hID0gV0FJVE5VTTtcbiAgICBjb21taXQobXlfdmVjKTtcbiAgICB3aGlsZSh3YXRjaC5nID09IHdhdGNoLmIgfHwgd2F0Y2guYSAhPSB3YXRjaC5nKSB7XG4gICAgICAvL3doaWxlKHdhdGNoLmcgPT0gd2F0Y2guYiB8fCB3YXRjaC5hICE9IDEyMykge1xuICAgICAgd2F0Y2ggPSByZWFkX2F0KHdhdGNoX2Nvb3Jkcyk7XG4gICAgfVxuICB9XG4gIGNvbW1pdChteV92ZWMpO1xufVxuYFxuIiwibW9kdWxlLmV4cG9ydHMgPSB7IGRvX2NoZWNrOiBgXG5pbnQgY2hlY2soaW50IHJvdywgaW50IG1pbl93ZWlnaHRfbWFnbml0dWRlKSB7XG4gIGludCBub25jZV9wcm9iZSwgaTtcbiAgaXZlYzIgcl90ZXhlbDtcbiAgbm9uY2VfcHJvYmUgPSBISUdIX0JJVFM7XG4gIGZvcihpID0gbWluX3dlaWdodF9tYWduaXR1ZGU7IGktLSA+IDA7ICkge1xuICAgIHJfdGV4ZWwgPSByZWFkX2F0KGl2ZWMyKEhBU0hfTEVOR1RIIC0gMSAtIGksIHJvdykpLmJhO1xuICAgIG5vbmNlX3Byb2JlICY9IH4ocl90ZXhlbC5zIF4gcl90ZXhlbC50KTtcbiAgICBpZihub25jZV9wcm9iZSA9PSAwKSBicmVhaztcbiAgfVxuICByZXR1cm4gbm9uY2VfcHJvYmU7XG59XG5gLCBrX2NoZWNrOiBgXG51bmlmb3JtIGludCBtaW5XZWlnaHRNYWduaXR1ZGU7XG52b2lkIG1haW4oKSB7XG4gIGluaXQoKTtcbiAgaXZlYzQgbXlfdmVjID0gcmVhZCgpO1xuICBpZihteV9jb29yZC54ID09IFNUQVRFX0xFTkdUSCkge1xuICAgIG15X3ZlYy5yID0gbWluV2VpZ2h0TWFnbml0dWRlO1xuICAgIG15X3ZlYy5hID0gY2hlY2sobXlfY29vcmQueSwgbWluV2VpZ2h0TWFnbml0dWRlKTtcbiAgfVxuICBjb21taXQobXlfdmVjKTtcbn1cbmAsIGNvbDogYFxudm9pZCBtYWluKCkge1xuICBpbml0KCk7XG4gIGl2ZWM0IG15X3ZlYyA9IHJlYWQoKTtcbiAgaW50IGk7XG4gIGlmKG15X2Nvb3JkLnggPT0gU1RBVEVfTEVOR1RIICYmIG15X2Nvb3JkLnkgPT0gMCkge1xuICAgIG15X3ZlYy5iID0gMDtcbiAgICBpZihteV92ZWMuYSA9PSAwKSB7XG4gICAgICBpdmVjNCByZWFkX3ZlYztcbiAgICAgIG15X3ZlYy5iID0gLTE7XG4gICAgICBmb3IoaSA9IDE7IGkgPCBpbnQoc2l6ZS55KTsgaSsrKSB7XG4gICAgICAgIHJlYWRfdmVjID0gcmVhZF9hdCggaXZlYzIoIFNUQVRFX0xFTkdUSCwgaSkpO1xuICAgICAgICBpZihyZWFkX3ZlYy5hICE9IDApIHtcbiAgICAgICAgICBteV92ZWMuYSA9IHJlYWRfdmVjLmE7XG4gICAgICAgICAgbXlfdmVjLmIgPSBpO1xuICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICB9XG4gIGNvbW1pdChteV92ZWMpO1xufVxuYFxufVxuIiwibW9kdWxlLmV4cG9ydHMgPSBgXG52b2lkIG1haW4oKSB7XG4gIGluaXQoKTtcbiAgaXZlYzQgbXlfdmVjID0gcmVhZCgpO1xuICBpZihteV9jb29yZC55ID09IDAgJiYgbXlfY29vcmQueCA9PSBTVEFURV9MRU5HVEgpIHtcbiAgICBteV92ZWMuZyA9IGNoZWNrKG15X3ZlYy5iLCBteV92ZWMucik7XG4gIH1cbiAgaWYobXlfY29vcmQueSA9PSAwICYmIG15X2Nvb3JkLnggPCBIQVNIX0xFTkdUSCkge1xuICAgIGl2ZWM0IGluZm9fdmVjID0gcmVhZF9hdChpdmVjMihTVEFURV9MRU5HVEgsIDApKTtcbiAgICBpbnQgbm9uY2VfcHJvYmUgPSBpbmZvX3ZlYy5hO1xuICAgIGludCByb3cgPSBpbmZvX3ZlYy5iO1xuICAgIGl2ZWM0IGhhc2hfdmVjID0gcmVhZF9hdChpdmVjMihteV9jb29yZC54LCByb3cpKTtcbiAgICBteV92ZWMuYSA9IChoYXNoX3ZlYy5yICYgbm9uY2VfcHJvYmUpID09IDA/IDEgOiAoKGhhc2hfdmVjLmcgJiBub25jZV9wcm9iZSkgPT0gMD8gLTEgOiAwKTtcbiAgfVxuICBjb21taXQobXlfdmVjKTtcbn1cbmBcbiIsIm1vZHVsZS5leHBvcnRzID0gXG5gI2RlZmluZSBIQVNIX0xFTkdUSCAyNDNcbiNkZWZpbmUgTlVNQkVSX09GX1JPVU5EUyA4MVxuI2RlZmluZSBJTkNSRU1FTlRfU1RBUlQgSEFTSF9MRU5HVEggLSA2NFxuI2RlZmluZSBTVEFURV9MRU5HVEggMyAqIEhBU0hfTEVOR1RIXG4jZGVmaW5lIEhBTEZfTEVOR1RIIDM2NFxuI2RlZmluZSBISUdIX0JJVFMgMHhGRkZGRkZGRlxuI2RlZmluZSBMT1dfQklUUyAweDAwMDAwMDAwXG5gXG4iLCJtb2R1bGUuZXhwb3J0cyA9IGBcbnZvaWQgbWFpbigpIHtcbiAgaW5pdCgpO1xuICBpdmVjNCBteV92ZWMgPSByZWFkKCk7XG4gIGlmKG15X2Nvb3JkLnggPj0gSU5DUkVNRU5UX1NUQVJUICYmIG15X2Nvb3JkLnggPCBIQVNIX0xFTkdUSCApIHtcbiAgICBteV92ZWMucmcgPSBnZXRfc3VtX3RvX2luZGV4KElOQ1JFTUVOVF9TVEFSVCwgSEFTSF9MRU5HVEgsIDEsIG15X2Nvb3JkLnkpO1xuICB9XG4gIGlmKG15X2Nvb3JkLnggPT0gU1RBVEVfTEVOR1RIICkge1xuICAgIG15X3ZlYy5yZyA9IGl2ZWMyKDApO1xuICB9XG4gIG15X3ZlYy5iYSA9IG15X3ZlYy5yZztcbiAgY29tbWl0KG15X3ZlYyk7XG59XG5gXG4iLCJjb25zdCBoZWFkZXJzICAgID0gcmVxdWlyZSggJy4vaGVhZGVycycpO1xuY29uc3QgZmluYWxpemUgICA9IHJlcXVpcmUoICcuL2ZpbmFsaXplJyk7XG5jb25zdCBiYXJyaWVyICAgID0gcmVxdWlyZSggJy4vYmFycmllcicpO1xuY29uc3QgdHdpc3QgICAgICA9IHJlcXVpcmUoICcuL3RyYW5zZm9ybScpO1xuY29uc3QgY2hlY2sgICAgICA9IHJlcXVpcmUoICcuL2NoZWNrJyk7XG5jb25zdCBhZGQgICAgICAgID0gcmVxdWlyZSggJy4vYWRkJyk7XG5jb25zdCBpbml0ICAgICAgID0gcmVxdWlyZSggJy4vaW5pdCcpO1xuY29uc3QgaW5jcmVtZW50ICA9IHJlcXVpcmUoICcuL2luY3JlbWVudCcpO1xuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgaW5pdCAgICAgIDogaGVhZGVycyArIGFkZCArIGluaXQsXG4gIGluY3JlbWVudCA6IGhlYWRlcnMgKyBhZGQgKyBpbmNyZW1lbnQsXG4gIHRyYW5zZm9ybSA6IGhlYWRlcnMgKyB0d2lzdCxcbiAgY29sX2NoZWNrIDogaGVhZGVycyArIGNoZWNrLmNvbCxcbiAgY2hlY2sgICAgIDogaGVhZGVycyArIGNoZWNrLmRvX2NoZWNrICsgY2hlY2sua19jaGVjayxcbiAgZmluYWxpemUgIDogaGVhZGVycyArIGNoZWNrLmRvX2NoZWNrICsgZmluYWxpemUsXG59XG4iLCJsZXQga19pbml0ID0gYFxudm9pZCBtYWluKCkge1xuICBpbml0KCk7XG4gIGNvbW1pdChvZmZzZXQoKSk7XG59XG5gXG5sZXQgb2Zmc2V0ID0gYFxudW5pZm9ybSBpbnQgZ3Jfb2Zmc2V0O1xuaXZlYzQgb2Zmc2V0KCkge1xuICBpZihteV9jb29yZC54ID49IEhBU0hfTEVOR1RIIC8gMyAmJiBteV9jb29yZC54IDwgSEFTSF9MRU5HVEggLyAzICogMiApIHtcbiAgICBpdmVjNCBteV92ZWM7XG4gICAgbXlfdmVjLnJnID0gZ2V0X3N1bV90b19pbmRleChIQVNIX0xFTkdUSCAvIDMsIEhBU0hfTEVOR1RIIC8gMyAqIDIsIG15X2Nvb3JkLnkgKyBncl9vZmZzZXQsIDApO1xuICAgIHJldHVybiBteV92ZWM7XG4gIH0gZWxzZSB7XG4gICAgcmV0dXJuIHJlYWRfYXQoaXZlYzIobXlfY29vcmQueCwwKSk7XG4gIH1cbn1cbmBcbm1vZHVsZS5leHBvcnRzID0gb2Zmc2V0ICsga19pbml0XG4iLCJsZXQgdHdpc3QgPSBgXG5pdmVjMiB0d2lzdCgpIHtcbiAgaW50IGFscGhhLCBiZXRhLCBnYW1tYSwgZGVsdGE7XG4gIGl2ZWM0IHYxLCB2MjtcbiAgaW50IGogPSBteV9jb29yZC54O1xuXG4gIHYxID0gcmVhZF9hdChpdmVjMihqID09IDA/IDA6KCgoaiAtIDEpJTIpKzEpKkhBTEZfTEVOR1RIIC0gKChqLTEpPj4xKSwgbXlfY29vcmQueSkpO1xuICB2MiA9IHJlYWRfYXQoaXZlYzIoKChqJTIpKzEpKkhBTEZfTEVOR1RIIC0gKChqKT4+MSksIG15X2Nvb3JkLnkpKTtcbiAgYWxwaGEgPSB2MS5iO1xuICBiZXRhID0gdjEuYTtcbiAgZ2FtbWEgPSB2Mi5hO1xuICBkZWx0YSA9IChhbHBoYSB8ICh+Z2FtbWEpKSAmICh2Mi5iIF4gYmV0YSk7Ly92Mi5iID09PSBzdGF0ZV9sb3dbdDJdXG5cbiAgcmV0dXJuIGl2ZWMyKH5kZWx0YSwgKGFscGhhIF4gZ2FtbWEpIHwgZGVsdGEpO1xufVxuYFxubGV0ICB0d2lzdE1haW4gPSBgXG52b2lkIG1haW4oKSB7XG4gIGluaXQoKTtcbiAgaXZlYzQgbXlfdmVjID0gcmVhZCgpO1xuICBpZihteV9jb29yZC54IDwgU1RBVEVfTEVOR1RIKVxuICAgIG15X3ZlYy5iYSA9IHR3aXN0KCk7XG4gIGNvbW1pdChteV92ZWMpO1xufVxuYFxuXG5sZXQga190cmFuc2Zvcm0gPSBgXG52b2lkIHRyYW5zZm9ybSgpIHtcbiAgaXZlYzIgc2NyYXRjaHBhZDtcbiAgaXZlYzQgc3RhdGUgPSByZWFkKCk7XG4gIGludCByb3VuZDtcbiAgZm9yKHJvdW5kID0gMDsgcm91bmQgPCBOVU1CRVJfT0ZfUk9VTkRTOyByb3VuZCsrKSB7XG4gICAgc2NyYXRjaHBhZCA9IHR3aXN0KCk7XG4gICAgLy9iYXJyaWVyKGl2ZWMyKFNUQVRFX0xFTkdUSCxteV9jb29yZC55KSwgMCk7XG4gICAgc3RhdGUuYiA9IHNjcmF0Y2hwYWQuczsvL3NwX2xvd1tpXTtcbiAgICBzdGF0ZS5hID0gc2NyYXRjaHBhZC50Oy8vc3BfaGlnaFtpXTtcbiAgICBjb21taXQoc3RhdGUpO1xuICAgIC8vYmFycmllcihpdmVjMihTVEFURV9MRU5HVEgsbXlfY29vcmQueSksIDApO1xuICB9XG59XG5gXG5cbm1vZHVsZS5leHBvcnRzID0gdHdpc3QgKyB0d2lzdE1haW5cbiJdLCJzb3VyY2VSb290IjoiIn0=