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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly8vd2VicGFjay91bml2ZXJzYWxNb2R1bGVEZWZpbml0aW9uIiwid2VicGFjazovLy93ZWJwYWNrL2Jvb3RzdHJhcCIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL2Flcy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL2NpcGhlci1jb3JlLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvY29yZS5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL2VuYy1iYXNlNjQuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9lbmMtdXRmMTYuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9ldnBrZGYuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9mb3JtYXQtaGV4LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvaG1hYy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL2luZGV4LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvbGliLXR5cGVkYXJyYXlzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvbWQ1LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvbW9kZS1jZmIuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9tb2RlLWN0ci1nbGFkbWFuLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvbW9kZS1jdHIuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9tb2RlLWVjYi5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL21vZGUtb2ZiLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvcGFkLWFuc2l4OTIzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvcGFkLWlzbzEwMTI2LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvcGFkLWlzbzk3OTcxLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvcGFkLW5vcGFkZGluZy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3BhZC16ZXJvcGFkZGluZy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3Bia2RmMi5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3JhYmJpdC1sZWdhY3kuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9yYWJiaXQuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9yYzQuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9yaXBlbWQxNjAuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2NyeXB0by1qcy9zaGExLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvc2hhMjI0LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvc2hhMjU2LmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9jcnlwdG8tanMvc2hhMy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3NoYTM4NC5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3NoYTUxMi5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3RyaXBsZWRlcy5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvY3J5cHRvLWpzL3g2NC1jb3JlLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvY3J5cHRvL2J1bmRsZS9idW5kbGUuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9jcnlwdG8vY29udmVydGVyL2NvbnZlcnRlci5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvaW90YS5jcnlwdG8uanMvbGliL2NyeXB0by9jb252ZXJ0ZXIvd29yZHMuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9jcnlwdG8vY3VybC9jdXJsLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvY3J5cHRvL2hlbHBlcnMvYWRkZXIuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9jcnlwdG8vaG1hYy9obWFjLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvY3J5cHRvL2tlcmwva2VybC5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvaW90YS5jcnlwdG8uanMvbGliL2NyeXB0by9zaWduaW5nL29sZFNpZ25pbmcuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9jcnlwdG8vc2lnbmluZy9zaWduaW5nLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvZXJyb3JzL2lucHV0RXJyb3JzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvaW90YS5jcnlwdG8uanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi9tdWx0aXNpZy9hZGRyZXNzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvbXVsdGlzaWcvbXVsdGlzaWcuanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi91dGlscy9hc2NpaVRvVHJ5dGVzLmpzIiwid2VicGFjazovLy8uL25vZGVfbW9kdWxlcy9pb3RhLmNyeXB0by5qcy9saWIvdXRpbHMvZXh0cmFjdEpzb24uanMiLCJ3ZWJwYWNrOi8vLy4vbm9kZV9tb2R1bGVzL2lvdGEuY3J5cHRvLmpzL2xpYi91dGlscy9pbnB1dFZhbGlkYXRvci5qcyIsIndlYnBhY2s6Ly8vLi9ub2RlX21vZHVsZXMvaW90YS5jcnlwdG8uanMvbGliL3V0aWxzL3V0aWxzLmpzIiwid2VicGFjazovLy8uL3NyYy9XZWJHTC9pbmRleC5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvV2ViR0wvaW5pdEdMLmpzIiwid2VicGFjazovLy8uL3NyYy9XZWJHTC9uZXdCdWZmZXIuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL1dlYkdML3NoYWRlcmNvZGUuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL1dlYkdML3RleHR1cmUuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL2NvbnN0YW50cy5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvY3VybC5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvY3VybC5saWIuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3BlYXJsZGl2ZXIuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NlYXJjaEluaXQuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvYWRkLmpzIiwid2VicGFjazovLy8uL3NyYy9zaGFkZXJzL2JhcnJpZXIuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvY2hlY2suanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvZmluYWxpemUuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvaGVhZGVycy5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvc2hhZGVycy9pbmNyZW1lbnQuanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvaW5kZXguanMiLCJ3ZWJwYWNrOi8vLy4vc3JjL3NoYWRlcnMvaW5pdC5qcyIsIndlYnBhY2s6Ly8vLi9zcmMvc2hhZGVycy90cmFuc2Zvcm0uanMiXSwibmFtZXMiOlsiaW5pdEdMIiwicmVxdWlyZSIsIm5ld0J1ZmZlciIsImNyZWF0ZVRleHR1cmUiLCJTaGFkZXJDb2RlIiwiX2ZyYW1lQnVmZmVyU2V0VGV4dHVyZSIsImdsIiwiZmJvIiwiblRleHR1cmUiLCJkaW0iLCJiaW5kRnJhbWVidWZmZXIiLCJGUkFNRUJVRkZFUiIsImZyYW1lYnVmZmVyVGV4dHVyZTJEIiwiQ09MT1JfQVRUQUNITUVOVDAiLCJURVhUVVJFXzJEIiwiZnJhbWVCdWZmZXJTdGF0dXMiLCJjaGVja0ZyYW1lYnVmZmVyU3RhdHVzIiwiRlJBTUVCVUZGRVJfQ09NUExFVEUiLCJFcnJvciIsIm1lc3NhZ2UiLCJhbGxvYyIsInN6IiwibnMiLCJNYXRoIiwicG93IiwiY2VpbCIsImxvZyIsImRhdGEiLCJJbnQzMkFycmF5IiwibGVuZ3RoIiwiX2JpbmRCdWZmZXJzIiwiYnVmZmVycyIsImF0dHJpYiIsImJpbmRCdWZmZXIiLCJBUlJBWV9CVUZGRVIiLCJ0ZXh0dXJlIiwiZW5hYmxlVmVydGV4QXR0cmliQXJyYXkiLCJ2ZXJ0ZXhBdHRyaWJQb2ludGVyIiwiRkxPQVQiLCJwb3NpdGlvbiIsIkVMRU1FTlRfQVJSQVlfQlVGRkVSIiwiaW5kZXgiLCJfY3JlYXRlVmVydGV4U2hhZGVyIiwidmVydGV4U2hhZGVyIiwiY3JlYXRlU2hhZGVyIiwiVkVSVEVYX1NIQURFUiIsInNoYWRlclNvdXJjZSIsInZlcnRleFNoYWRlckNvZGUiLCJjb21waWxlU2hhZGVyIiwiZ2V0U2hhZGVyUGFyYW1ldGVyIiwiQ09NUElMRV9TVEFUVVMiLCJnZXRTaGFkZXJJbmZvTG9nIiwiX2NyZWF0ZUZyYWdtZW50U2hhZGVyIiwiY29kZSIsImZyYWdtZW50U2hhZGVyIiwiRlJBR01FTlRfU0hBREVSIiwic3RkbGliIiwiTE9DIiwic3BsaXQiLCJkYmdNc2ciLCJubCIsIl9maW5pc2hSdW4iLCJiaW5kVmVydGV4QXJyYXkiLCJiaW5kVGV4dHVyZSIsIldlYkdMV29ya2VyIiwibCIsInMiLCJ3b3JrZXIiLCJPYmplY3QiLCJ4IiwieSIsIk1BWElNQUdFU0laRSIsIk1BWF9URVhUVVJFX1NJWkUiLCJJTUFHRV9TSVpFIiwiZmxvb3IiLCJwcm9ncmFtcyIsIk1hcCIsImlwdCIsIlVpbnQxNkFycmF5IiwidmFvIiwiY3JlYXRlVmVydGV4QXJyYXkiLCJmcmFtZWJ1ZmZlciIsImNyZWF0ZUZyYW1lYnVmZmVyIiwidGV4dHVyZTAiLCJ0ZXh0dXJlMSIsIm1vZHVsZSIsImV4cG9ydHMiLCJhZGRQcm9ncmFtIiwibmFtZSIsInVuaWZvcm1zIiwicHJvZ3JhbSIsImNyZWF0ZVByb2dyYW0iLCJhdHRhY2hTaGFkZXIiLCJiaW5kQXR0cmliTG9jYXRpb24iLCJsaW5rUHJvZ3JhbSIsInVfdmFycyIsInZhcmlhYmxlIiwic2V0IiwiZ2V0VW5pZm9ybUxvY2F0aW9uIiwiZ2V0IiwiY29uc29sZSIsInJ1biIsImNvdW50IiwiaW5mbyIsImdldFByb2dyYW1QYXJhbWV0ZXIiLCJMSU5LX1NUQVRVUyIsInVUZXh0dXJlIiwidXNlUHJvZ3JhbSIsImFjdGl2ZVRleHR1cmUiLCJURVhUVVJFMCIsInVuaWZvcm0xaSIsInZpZXdwb3J0IiwidV92IiwibiIsInYiLCJkcmF3RWxlbWVudHMiLCJUUklBTkdMRVMiLCJVTlNJR05FRF9TSE9SVCIsInRleDAiLCJyZWFkRGF0YSIsIk4iLCJNIiwicmVhZFBpeGVscyIsIlJHQkFfSU5URUdFUiIsIklOVCIsInN1YmFycmF5Iiwid3JpdGVEYXRhIiwidGV4SW1hZ2UyRCIsIlJHQkEzMkkiLCJjYW52YXMiLCJkb2N1bWVudCIsImNyZWF0ZUVsZW1lbnQiLCJhdHRyIiwiYWxwaGEiLCJhbnRpYWxpYXMiLCJnZXRDb250ZXh0IiwiZiIsImUiLCJidWYiLCJjcmVhdGVCdWZmZXIiLCJidWZmZXJEYXRhIiwiRmxvYXQzMkFycmF5IiwiU1RBVElDX0RSQVciLCJ0ZXhQYXJhbWV0ZXJpIiwiVEVYVFVSRV9XUkFQX1MiLCJDTEFNUF9UT19FREdFIiwiVEVYVFVSRV9XUkFQX1QiLCJURVhUVVJFX01JTl9GSUxURVIiLCJORUFSRVNUIiwiVEVYVFVSRV9NQUdfRklMVEVSIiwiSEFTSF9MRU5HVEgiLCJJTlRfTEVOR1RIIiwiTk9OQ0VfTEVOR1RIIiwiVElNRVNUQU1QX1NUQVJUIiwiVElNRVNUQU1QX0xPV0VSX0JPVU5EX1NUQVJUIiwiVElNRVNUQU1QX1VQUEVSX0JPVU5EX1NUQVJUIiwiTk9OQ0VfU1RBUlQiLCJTVEFURV9MRU5HVEgiLCJOVU1CRVJfT0ZfUk9VTkRTIiwiVFJBTlNBQ1RJT05fTEVOR1RIIiwiQ29uc3QiLCJDdXJsIiwic3RhdGUiLCJ0cnV0aFRhYmxlIiwiSW50OEFycmF5IiwiaW5pdGlhbGl6ZSIsInJlc2V0IiwicHJvdG90eXBlIiwiZmlsbCIsImFic29yYiIsInRyaXRzIiwib2Zmc2V0IiwiaSIsImxpbWl0IiwidHJhbnNmb3JtIiwic3F1ZWV6ZSIsInN0YXRlQ29weSIsInJvdW5kIiwic2xpY2UiLCJQZWFybERpdmVyIiwiQ29udmVydGVyIiwiY29udmVydGVyIiwiTk9OQ0VfVElNRVNUQU1QX0xPV0VSX0JPVU5EIiwiTk9OQ0VfVElNRVNUQU1QX1VQUEVSX0JPVU5EIiwiZnJvbVZhbHVlIiwiTUFYX1RJTUVTVEFNUF9WQUxVRSIsInBkSW5zdGFuY2UiLCJvcHRpb25zIiwic3VjY2VzcyIsImVycm9yIiwicHJlcGFyZSIsInRyeXRlcyIsIm9mZnNldFN0YXRlIiwicG93UHJvbWlzZSIsInNlYXJjaCIsIm1pbldlaWdodCIsInRoZW4iLCJjYXRjaCIsIlRBR19UUklOQVJZX1NUQVJUIiwiVEFHX1RSSU5BUllfU0laRSIsInNldFRpbWVzdGFtcCIsInRpbWVzdGFtcCIsInVwcGVyIiwiRGF0ZSIsIm5vdyIsIm1hcCIsIm92ZXJyaWRlQXR0YWNoVG9UYW5nbGUiLCJpb3RhIiwiYXBpIiwiYXR0YWNoVG9UYW5nbGUiLCJ0cnVua1RyYW5zYWN0aW9uIiwiYnJhbmNoVHJhbnNhY3Rpb24iLCJjYWxsYmFjayIsImNjdXJsSGFzaGluZyIsImlvdGFPYmoiLCJ2YWxpZCIsImlzSGFzaCIsImlzVmFsdWUiLCJmaW5hbEJ1bmRsZVRyeXRlcyIsInByZXZpb3VzVHhIYXNoIiwibG9vcFRyeXRlcyIsImdldEJ1bmRsZVRyeXRlcyIsInJldmVyc2UiLCJ0aGlzVHJ5dGVzIiwidHhPYmplY3QiLCJ1dGlscyIsInRyYW5zYWN0aW9uT2JqZWN0IiwidGFnIiwib2Jzb2xldGVUYWciLCJhdHRhY2htZW50VGltZXN0YW1wIiwiYXR0YWNobWVudFRpbWVzdGFtcExvd2VyQm91bmQiLCJhdHRhY2htZW50VGltZXN0YW1wVXBwZXJCb3VuZCIsImxhc3RJbmRleCIsImN1cnJlbnRJbmRleCIsIm5ld1RyeXRlcyIsInRyYW5zYWN0aW9uVHJ5dGVzIiwiY3VybCIsIm5vbmNlIiwicmV0dXJuZWRUcnl0ZXMiLCJzdWJzdHIiLCJjb25jYXQiLCJuZXdUeE9iamVjdCIsInR4SGFzaCIsImhhc2giLCJwdXNoIiwid2luZG93IiwiaW5pdCIsImluc3RhbmNlIiwic2V0T2Zmc2V0IiwibyIsImludGVycnVwdCIsInJlc3VtZSIsImRvTmV4dCIsInJlbW92ZSIsInF1ZXVlIiwidW5zaGlmdCIsIldlYkdMIiwiU2VhcmNoSW5pdCIsIktSTkwiLCJURVhFTFNJWkUiLCJQRFN0YXRlIiwiUkVBRFkiLCJTRUFSQ0hJTkciLCJJTlRFUlJVUFRFRCIsInBhY2siLCJyIiwiayIsInBlYXJsRGl2ZXJDYWxsYmFjayIsInJlcyIsInRyYW5zYWN0aW9uVHJpdHMiLCJtaW5XZWlnaHRNYWduaXR1ZGUiLCJtX3NlbGYiLCJzZWFyY2hPYmplY3QiLCJQZWFybERpdmVySW5zdGFuY2UiLCJjb250ZXh0IiwiaW5jcmVtZW50IiwiY2hlY2siLCJjb2xfY2hlY2siLCJmaW5hbGl6ZSIsInN0YXRlcyIsIlByb21pc2UiLCJyZWplY3QiLCJyZWoiLCJtd20iLCJjYWxsIiwibmV4dCIsInNoaWZ0IiwiX1dlYkdMRmluZE5vbmNlIiwiX3NhdmUiLCJyZWR1Y2UiLCJhIiwiYyIsImZvckVhY2giLCJfV2ViR0xXcml0ZUJ1ZmZlcnMiLCJsb3ciLCJoaWdoIiwiX1dlYkdMU2VhcmNoIiwic2V0VGltZW91dCIsInNlYXJjaFdpdGhDYWxsYmFjayIsImVyciIsInRvUGFpciIsIlRSWVRFX0xFTkdUSCIsIkxPV19CSVRTIiwiSElHSF9CSVRTIiwiTE9XXzAiLCJMT1dfMSIsIkxPV18yIiwiTE9XXzMiLCJISUdIXzAiLCJISUdIXzEiLCJISUdIXzIiLCJISUdIXzMiLCJ0cml0Iiwic2NyYXRjaHBhZEhpZ2giLCJzY3JhdGNocGFkTG93Iiwic2NyYXRjaHBhZEluZGV4Iiwic3RhdGVJbmRleCIsImJldGEiLCJnYW1tYSIsImRlbHRhIiwiZG9fY2hlY2siLCJrX2NoZWNrIiwiY29sIiwiaGVhZGVycyIsImJhcnJpZXIiLCJ0d2lzdCIsImFkZCIsImtfaW5pdCIsInR3aXN0TWFpbiIsImtfdHJhbnNmb3JtIl0sIm1hcHBpbmdzIjoiQUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxDQUFDO0FBQ0QsTztBQ1ZBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOzs7QUFHQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxhQUFLO0FBQ0w7QUFDQTs7QUFFQTtBQUNBO0FBQ0EseURBQWlELGNBQWM7QUFDL0Q7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsbUNBQTJCLDBCQUEwQixFQUFFO0FBQ3ZELHlDQUFpQyxlQUFlO0FBQ2hEO0FBQ0E7QUFDQTs7QUFFQTtBQUNBLDhEQUFzRCwrREFBK0Q7O0FBRXJIO0FBQ0E7OztBQUdBO0FBQ0E7Ozs7Ozs7Ozs7OztBQ25FQSxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FB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QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxNQUFNO0FBQ04sRUFBRTs7O0FBR0YsQ0FBQyxHOzs7Ozs7Ozs7OztBQzlJRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDs7QUFFQSxDQUFDLEc7Ozs7Ozs7Ozs7O0FDakJELENBQUM7QUFDRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFFBT0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLDRCQUE0QiwwQkFBMEI7QUFDdEQ7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsVUFBVTtBQUNWO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EsRUFBRTs7O0FBR0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQzNFRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSx3QkFBd0IsUUFBUTtBQUNoQztBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQSw0QkFBNEIsUUFBUTtBQUNwQztBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQSw0QkFBNEIsT0FBTztBQUNuQztBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLE1BQU07O0FBRU47QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsZ0JBQWdCLGlCQUFpQjtBQUNqQztBQUNBLGlCQUFpQixVQUFVO0FBQzNCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSxnQkFBZ0IsaUJBQWlCO0FBQ2pDLGdCQUFnQixpQkFBaUI7QUFDakM7QUFDQSxpQkFBaUIsVUFBVTtBQUMzQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsRUFBRTs7O0FBR0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQzNRRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxVQUFVO0FBQ1Y7QUFDQTtBQUNBOztBQUVBO0FBQ0Esd0JBQXdCLGVBQWU7QUFDdkM7QUFDQTtBQUNBOztBQUVBO0FBQ0EsRUFBRTs7O0FBR0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQzdFRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0Esd0NBQXdDO0FBQ3hDO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLGVBQWU7QUFDM0M7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjs7QUFFQTtBQUNBLEVBQUU7Ozs7O0FBS0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQ25IRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQSw0QkFBNEIsZUFBZTtBQUMzQztBQUNBO0FBQ0E7QUFDQSxNQUFNOztBQUVOOztBQUVBO0FBQ0EsRUFBRTs7O0FBR0Y7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQ3pERCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQTtBQUNBLE1BQU07O0FBRU47QUFDQSxFQUFFOzs7QUFHRjs7QUFFQSxDQUFDLEc7Ozs7Ozs7Ozs7O0FDdkNELENBQUM7QUFDRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFFBT0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLGVBQWU7QUFDM0M7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjs7QUFFQTtBQUNBLEVBQUU7OztBQUdGOztBQUVBLENBQUMsRzs7Ozs7Ozs7Ozs7QUNyREQsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFPQTtBQUNBLENBQUM7O0FBRUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQSxNQUFNOztBQUVOO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQ2hERCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLE1BQU07O0FBRU47QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTs7QUFFQSxDQUFDLEc7Ozs7Ozs7Ozs7O0FDM0NELENBQUM7QUFDRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFFBT0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxNQUFNOztBQUVOO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQ3ZDRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7OztBQUdBOztBQUVBLENBQUMsRzs7Ozs7Ozs7Ozs7QUM3QkQsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFPQTtBQUNBLENBQUM7O0FBRUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7O0FBRUEsQ0FBQyxHOzs7Ozs7Ozs7OztBQzVDRCxDQUFDO0FBQ0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQSxRQU9BO0FBQ0EsQ0FBQzs7QUFFRDtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7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QTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVOztBQUVWOztBQUVBO0FBQ0EsNEJBQTRCLFFBQVE7QUFDcEM7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsNEJBQTRCLFFBQVE7QUFDcEM7QUFDQTtBQUNBO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCLE9BQU87QUFDekI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0Esa0JBQWtCLE9BQU87QUFDekI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLE9BQU87QUFDbkM7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLE1BQU07OztBQUdOO0FBQ0E7O0FBRUE7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTs7QUFFQTtBQUNBO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQTtBQUNBLGdCQUFnQixpQkFBaUI7QUFDakM7QUFDQSxpQkFBaUIsVUFBVTtBQUMzQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsZ0JBQWdCLGlCQUFpQjtBQUNqQyxnQkFBZ0IsaUJBQWlCO0FBQ2pDO0FBQ0EsaUJBQWlCLFVBQVU7QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEVBQUU7OztBQUdGOztBQUVBLENBQUMsRzs7Ozs7Ozs7Ozs7QUMxUUQsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFPQTtBQUNBLENBQUM7O0FBRUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7O0FBRVY7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBLDRCQUE0QixRQUFRO0FBQ3BDO0FBQ0E7QUFDQSxrQkFBa0I7QUFDbEI7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQjtBQUNsQjtBQUNBLGtCQUFrQjtBQUNsQjtBQUNBLGtCQUFrQjtBQUNsQjtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQSxnQkFBZ0IsaUJBQWlCO0FBQ2pDO0FBQ0EsaUJBQWlCLFVBQVU7QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLGdCQUFnQixpQkFBaUI7QUFDakMsZ0JBQWdCLGlCQUFpQjtBQUNqQztBQUNBLGlCQUFpQixVQUFVO0FBQzNCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxFQUFFOzs7QUFHRjs7QUFFQSxDQUFDLEc7Ozs7Ozs7Ozs7O0FDckpELENBQUM7QUFDRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFFBT0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7O0FBRVY7QUFDQTs7QUFFQTs7QUFFQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQSxnQkFBZ0IsaUJBQWlCO0FBQ2pDO0FBQ0EsaUJBQWlCLFVBQVU7QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLGdCQUFnQixpQkFBaUI7QUFDakMsZ0JBQWdCLGlCQUFpQjtBQUNqQztBQUNBLGlCQUFpQixVQUFVO0FBQzNCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxFQUFFOzs7QUFHRjs7QUFFQSxDQUFDLEc7Ozs7Ozs7Ozs7O0FDL0VELENBQUM7QUFDRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFFBT0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGlDQUFpQyxpQkFBaUI7QUFDbEQ7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxNQUFNOztBQUVOO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLFFBQVE7QUFDcEM7QUFDQTtBQUNBLGtCQUFrQjtBQUNsQjtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQSxnQkFBZ0IsaUJBQWlCO0FBQ2pDO0FBQ0EsaUJBQWlCLFVBQVU7QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLGdCQUFnQixpQkFBaUI7QUFDakMsZ0JBQWdCLGlCQUFpQjtBQUNqQztBQUNBLGlCQUFpQixVQUFVO0FBQzNCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxFQUFFOzs7QUFHRjs7QUFFQSxDQUFDLEc7Ozs7Ozs7Ozs7O0FDdE1ELENBQUM7QUFDRDtBQUNBO0FBQ0E7QUFDQTtBQUNBLFFBT0E7QUFDQSxDQUFDOztBQUVEO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHdCQUF3QixRQUFRO0FBQ2hDOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQSx3QkFBd0IsT0FBTztBQUMvQiw0QkFBNEIsT0FBTztBQUNuQztBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLHdCQUF3QixRQUFRO0FBQ2hDO0FBQ0E7O0FBRUEsNEJBQTRCLE9BQU87QUFDbkM7QUFDQTtBQUNBO0FBQ0E7QUFDQSxzQkFBc0I7QUFDdEI7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esa0JBQWtCO0FBQ2xCO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQSx3QkFBd0IsUUFBUTtBQUNoQztBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHVCQUF1QixPQUFPO0FBQzlCO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7O0FBRVY7QUFDQTtBQUNBLDRCQUE0QixRQUFRO0FBQ3BDO0FBQ0E7O0FBRUE7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLHFCQUFxQjtBQUNqRDtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQSxnQ0FBZ0MsWUFBWTtBQUM1QztBQUNBLGdDQUFnQyxPQUFPO0FBQ3ZDO0FBQ0E7QUFDQSxvQ0FBb0MsT0FBTztBQUMzQztBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsZ0NBQWdDLE9BQU87QUFDdkM7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSxvQ0FBb0MsT0FBTztBQUMzQztBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0Esd0NBQXdDLGdCQUFnQjtBQUN4RDtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esc0JBQXNCO0FBQ3RCO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQSxnQ0FBZ0MsT0FBTztBQUN2QyxvQ0FBb0MsT0FBTztBQUMzQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLDRCQUE0Qix1QkFBdUI7QUFDbkQ7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7O0FBRUE7QUFDQSw0QkFBNEIsUUFBUTtBQUNwQztBQUNBOztBQUVBO0FBQ0E7QUFDQSxNQUFNOztBQUVOO0FBQ0E7QUFDQTtBQUNBLGdCQUFnQixpQkFBaUI7QUFDakM7QUFDQSxpQkFBaUIsVUFBVTtBQUMzQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsZ0JBQWdCLGlCQUFpQjtBQUNqQyxnQkFBZ0IsaUJBQWlCO0FBQ2pDO0FBQ0EsaUJBQWlCLFVBQVU7QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEVBQUU7OztBQUdGOztBQUVBLENBQUMsRzs7Ozs7Ozs7Ozs7QUNsVUQsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFPQTtBQUNBLENBQUM7O0FBRUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBOztBQUVBOztBQUVBO0FBQ0E7QUFDQSxNQUFNOztBQUVOO0FBQ0E7QUFDQTtBQUNBLGdCQUFnQixpQkFBaUI7QUFDakM7QUFDQSxpQkFBaUIsVUFBVTtBQUMzQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsZ0JBQWdCLGlCQUFpQjtBQUNqQyxnQkFBZ0IsaUJBQWlCO0FBQ2pDO0FBQ0EsaUJBQWlCLFVBQVU7QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEVBQUU7OztBQUdGOztBQUVBLENBQUMsRzs7Ozs7Ozs7Ozs7QUNsRkQsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFPQTtBQUNBLENBQUM7O0FBRUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQSx3QkFBd0IsUUFBUTtBQUNoQztBQUNBO0FBQ0EsTUFBTTs7QUFFTjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNEJBQTRCLFFBQVE7QUFDcEM7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGtCQUFrQjtBQUNsQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTs7QUFFVjtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSxVQUFVOztBQUVWO0FBQ0E7QUFDQTs7QUFFQTtBQUNBLFVBQVU7O0FBRVY7QUFDQSxNQUFNOztBQUVOO0FBQ0E7QUFDQTtBQUNBLGdCQUFnQixpQkFBaUI7QUFDakM7QUFDQSxpQkFBaUIsVUFBVTtBQUMzQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsZ0JBQWdCLGlCQUFpQjtBQUNqQyxnQkFBZ0IsaUJBQWlCO0FBQ2pDO0FBQ0EsaUJBQWlCLFVBQVU7QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLEVBQUU7OztBQUdGOztBQUVBLENBQUMsRzs7Ozs7Ozs7Ozs7QUNsVUQsQ0FBQztBQUNEO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFPQTtBQUNBLENBQUM7O0FBRUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTtBQUNWO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVO0FBQ1Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7QUFDVjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTtBQUNWO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxVQUFVO0FBQ1Y7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFVBQVU7QUFDVjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsVUFBVTtBQUNWO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNB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QU1vVSxRQUFhLG1CQUFBcFUsQ0FBUywrQ0FBVCxDQUFuQjtBQUNBLElBQU1tUixRQUFhLG1CQUFBblIsQ0FBUyx1Q0FBVCxDQUFuQjtBQUNBLElBQU1xVSxNQUFhLG1CQUFBclUsQ0FBUyxtQ0FBVCxDQUFuQjtBQUNBLElBQU1xUCxPQUFhLG1CQUFBclAsQ0FBUyxxQ0FBVCxDQUFuQjtBQUNBLElBQU1rUixZQUFhLG1CQUFBbFIsQ0FBUywrQ0FBVCxDQUFuQjs7QUFFQW9GLE9BQU9DLE9BQVAsR0FBaUI7QUFDZmdLLFFBQVk2RSxVQUFVRyxHQUFWLEdBQWdCaEYsSUFEYjtBQUVmNkIsYUFBWWdELFVBQVVHLEdBQVYsR0FBZ0JuRCxTQUZiO0FBR2ZyRyxhQUFZcUosVUFBVUUsS0FIUDtBQUlmaEQsYUFBWThDLFVBQVUvQyxNQUFNOEMsR0FKYjtBQUtmOUMsU0FBWStDLFVBQVUvQyxNQUFNNEMsUUFBaEIsR0FBMkI1QyxNQUFNNkMsT0FMOUI7QUFNZjNDLFlBQVk2QyxVQUFVL0MsTUFBTTRDLFFBQWhCLEdBQTJCMUM7QUFOeEIsQ0FBakIsQzs7Ozs7Ozs7Ozs7Ozs7QUNUQSxJQUFJaUQsK0RBQUo7QUFNQSxJQUFJNUosNFVBQUo7QUFZQXRGLE9BQU9DLE9BQVAsR0FBaUJxRixTQUFTNEosTUFBMUIsQzs7Ozs7Ozs7Ozs7Ozs7QUNsQkEsSUFBSUYsdWJBQUo7QUFnQkEsSUFBS0cscUpBQUw7O0FBVUEsSUFBSUMseVlBQUo7O0FBZ0JBcFAsT0FBT0MsT0FBUCxHQUFpQitPLFFBQVFHLFNBQXpCLEMiLCJmaWxlIjoiY3VybC5saWIuanMiLCJzb3VyY2VzQ29udGVudCI6WyIoZnVuY3Rpb24gd2VicGFja1VuaXZlcnNhbE1vZHVsZURlZmluaXRpb24ocm9vdCwgZmFjdG9yeSkge1xuXHRpZih0eXBlb2YgZXhwb3J0cyA9PT0gJ29iamVjdCcgJiYgdHlwZW9mIG1vZHVsZSA9PT0gJ29iamVjdCcpXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBmYWN0b3J5KCk7XG5cdGVsc2UgaWYodHlwZW9mIGRlZmluZSA9PT0gJ2Z1bmN0aW9uJyAmJiBkZWZpbmUuYW1kKVxuXHRcdGRlZmluZShbXSwgZmFjdG9yeSk7XG5cdGVsc2Uge1xuXHRcdHZhciBhID0gZmFjdG9yeSgpO1xuXHRcdGZvcih2YXIgaSBpbiBhKSAodHlwZW9mIGV4cG9ydHMgPT09ICdvYmplY3QnID8gZXhwb3J0cyA6IHJvb3QpW2ldID0gYVtpXTtcblx0fVxufSkod2luZG93LCBmdW5jdGlvbigpIHtcbnJldHVybiAiLCIgXHQvLyBUaGUgbW9kdWxlIGNhY2hlXG4gXHR2YXIgaW5zdGFsbGVkTW9kdWxlcyA9IHt9O1xuXG4gXHQvLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuIFx0ZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXG4gXHRcdC8vIENoZWNrIGlmIG1vZHVsZSBpcyBpbiBjYWNoZVxuIFx0XHRpZihpbnN0YWxsZWRNb2R1bGVzW21vZHVsZUlkXSkge1xuIFx0XHRcdHJldHVybiBpbnN0YWxsZWRNb2R1bGVzW21vZHVsZUlkXS5leHBvcnRzO1xuIFx0XHR9XG4gXHRcdC8vIENyZWF0ZSBhIG5ldyBtb2R1bGUgKGFuZCBwdXQgaXQgaW50byB0aGUgY2FjaGUpXG4gXHRcdHZhciBtb2R1bGUgPSBpbnN0YWxsZWRNb2R1bGVzW21vZHVsZUlkXSA9IHtcbiBcdFx0XHRpOiBtb2R1bGVJZCxcbiBcdFx0XHRsOiBmYWxzZSxcbiBcdFx0XHRleHBvcnRzOiB7fVxuIFx0XHR9O1xuXG4gXHRcdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuIFx0XHRtb2R1bGVzW21vZHVsZUlkXS5jYWxsKG1vZHVsZS5leHBvcnRzLCBtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuIFx0XHQvLyBGbGFnIHRoZSBtb2R1bGUgYXMgbG9hZGVkXG4gXHRcdG1vZHVsZS5sID0gdHJ1ZTtcblxuIFx0XHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuIFx0XHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG4gXHR9XG5cblxuIFx0Ly8gZXhwb3NlIHRoZSBtb2R1bGVzIG9iamVjdCAoX193ZWJwYWNrX21vZHVsZXNfXylcbiBcdF9fd2VicGFja19yZXF1aXJlX18ubSA9IG1vZHVsZXM7XG5cbiBcdC8vIGV4cG9zZSB0aGUgbW9kdWxlIGNhY2hlXG4gXHRfX3dlYnBhY2tfcmVxdWlyZV9fLmMgPSBpbnN0YWxsZWRNb2R1bGVzO1xuXG4gXHQvLyBkZWZpbmUgZ2V0dGVyIGZ1bmN0aW9uIGZvciBoYXJtb255IGV4cG9ydHNcbiBcdF9fd2VicGFja19yZXF1aXJlX18uZCA9IGZ1bmN0aW9uKGV4cG9ydHMsIG5hbWUsIGdldHRlcikge1xuIFx0XHRpZighX193ZWJwYWNrX3JlcXVpcmVfXy5vKGV4cG9ydHMsIG5hbWUpKSB7XG4gXHRcdFx0T2JqZWN0LmRlZmluZVByb3BlcnR5KGV4cG9ydHMsIG5hbWUsIHtcbiBcdFx0XHRcdGNvbmZpZ3VyYWJsZTogZmFsc2UsXG4gXHRcdFx0XHRlbnVtZXJhYmxlOiB0cnVlLFxuIFx0XHRcdFx0Z2V0OiBnZXR0ZXJcbiBcdFx0XHR9KTtcbiBcdFx0fVxuIFx0fTtcblxuIFx0Ly8gZGVmaW5lIF9fZXNNb2R1bGUgb24gZXhwb3J0c1xuIFx0X193ZWJwYWNrX3JlcXVpcmVfXy5yID0gZnVuY3Rpb24oZXhwb3J0cykge1xuIFx0XHRPYmplY3QuZGVmaW5lUHJvcGVydHkoZXhwb3J0cywgJ19fZXNNb2R1bGUnLCB7IHZhbHVlOiB0cnVlIH0pO1xuIFx0fTtcblxuIFx0Ly8gZ2V0RGVmYXVsdEV4cG9ydCBmdW5jdGlvbiBmb3IgY29tcGF0aWJpbGl0eSB3aXRoIG5vbi1oYXJtb255IG1vZHVsZXNcbiBcdF9fd2VicGFja19yZXF1aXJlX18ubiA9IGZ1bmN0aW9uKG1vZHVsZSkge1xuIFx0XHR2YXIgZ2V0dGVyID0gbW9kdWxlICYmIG1vZHVsZS5fX2VzTW9kdWxlID9cbiBcdFx0XHRmdW5jdGlvbiBnZXREZWZhdWx0KCkgeyByZXR1cm4gbW9kdWxlWydkZWZhdWx0J107IH0gOlxuIFx0XHRcdGZ1bmN0aW9uIGdldE1vZHVsZUV4cG9ydHMoKSB7IHJldHVybiBtb2R1bGU7IH07XG4gXHRcdF9fd2VicGFja19yZXF1aXJlX18uZChnZXR0ZXIsICdhJywgZ2V0dGVyKTtcbiBcdFx0cmV0dXJuIGdldHRlcjtcbiBcdH07XG5cbiBcdC8vIE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbFxuIFx0X193ZWJwYWNrX3JlcXVpcmVfXy5vID0gZnVuY3Rpb24ob2JqZWN0LCBwcm9wZXJ0eSkgeyByZXR1cm4gT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iamVjdCwgcHJvcGVydHkpOyB9O1xuXG4gXHQvLyBfX3dlYnBhY2tfcHVibGljX3BhdGhfX1xuIFx0X193ZWJwYWNrX3JlcXVpcmVfXy5wID0gXCIvZGlzdFwiO1xuXG5cbiBcdC8vIExvYWQgZW50cnkgbW9kdWxlIGFuZCByZXR1cm4gZXhwb3J0c1xuIFx0cmV0dXJuIF9fd2VicGFja19yZXF1aXJlX18oX193ZWJwYWNrX3JlcXVpcmVfXy5zID0gXCIuL3NyYy9jdXJsLmxpYi5qc1wiKTtcbiIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9lbmMtYmFzZTY0XCIpLCByZXF1aXJlKFwiLi9tZDVcIiksIHJlcXVpcmUoXCIuL2V2cGtkZlwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vZW5jLWJhc2U2NFwiLCBcIi4vbWQ1XCIsIFwiLi9ldnBrZGZcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgQmxvY2tDaXBoZXIgPSBDX2xpYi5CbG9ja0NpcGhlcjtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cblx0ICAgIC8vIExvb2t1cCB0YWJsZXNcblx0ICAgIHZhciBTQk9YID0gW107XG5cdCAgICB2YXIgSU5WX1NCT1ggPSBbXTtcblx0ICAgIHZhciBTVUJfTUlYXzAgPSBbXTtcblx0ICAgIHZhciBTVUJfTUlYXzEgPSBbXTtcblx0ICAgIHZhciBTVUJfTUlYXzIgPSBbXTtcblx0ICAgIHZhciBTVUJfTUlYXzMgPSBbXTtcblx0ICAgIHZhciBJTlZfU1VCX01JWF8wID0gW107XG5cdCAgICB2YXIgSU5WX1NVQl9NSVhfMSA9IFtdO1xuXHQgICAgdmFyIElOVl9TVUJfTUlYXzIgPSBbXTtcblx0ICAgIHZhciBJTlZfU1VCX01JWF8zID0gW107XG5cblx0ICAgIC8vIENvbXB1dGUgbG9va3VwIHRhYmxlc1xuXHQgICAgKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAvLyBDb21wdXRlIGRvdWJsZSB0YWJsZVxuXHQgICAgICAgIHZhciBkID0gW107XG5cdCAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNTY7IGkrKykge1xuXHQgICAgICAgICAgICBpZiAoaSA8IDEyOCkge1xuXHQgICAgICAgICAgICAgICAgZFtpXSA9IGkgPDwgMTtcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIGRbaV0gPSAoaSA8PCAxKSBeIDB4MTFiO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gV2FsayBHRigyXjgpXG5cdCAgICAgICAgdmFyIHggPSAwO1xuXHQgICAgICAgIHZhciB4aSA9IDA7XG5cdCAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNTY7IGkrKykge1xuXHQgICAgICAgICAgICAvLyBDb21wdXRlIHNib3hcblx0ICAgICAgICAgICAgdmFyIHN4ID0geGkgXiAoeGkgPDwgMSkgXiAoeGkgPDwgMikgXiAoeGkgPDwgMykgXiAoeGkgPDwgNCk7XG5cdCAgICAgICAgICAgIHN4ID0gKHN4ID4+PiA4KSBeIChzeCAmIDB4ZmYpIF4gMHg2Mztcblx0ICAgICAgICAgICAgU0JPWFt4XSA9IHN4O1xuXHQgICAgICAgICAgICBJTlZfU0JPWFtzeF0gPSB4O1xuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgbXVsdGlwbGljYXRpb25cblx0ICAgICAgICAgICAgdmFyIHgyID0gZFt4XTtcblx0ICAgICAgICAgICAgdmFyIHg0ID0gZFt4Ml07XG5cdCAgICAgICAgICAgIHZhciB4OCA9IGRbeDRdO1xuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgc3ViIGJ5dGVzLCBtaXggY29sdW1ucyB0YWJsZXNcblx0ICAgICAgICAgICAgdmFyIHQgPSAoZFtzeF0gKiAweDEwMSkgXiAoc3ggKiAweDEwMTAxMDApO1xuXHQgICAgICAgICAgICBTVUJfTUlYXzBbeF0gPSAodCA8PCAyNCkgfCAodCA+Pj4gOCk7XG5cdCAgICAgICAgICAgIFNVQl9NSVhfMVt4XSA9ICh0IDw8IDE2KSB8ICh0ID4+PiAxNik7XG5cdCAgICAgICAgICAgIFNVQl9NSVhfMlt4XSA9ICh0IDw8IDgpICB8ICh0ID4+PiAyNCk7XG5cdCAgICAgICAgICAgIFNVQl9NSVhfM1t4XSA9IHQ7XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBpbnYgc3ViIGJ5dGVzLCBpbnYgbWl4IGNvbHVtbnMgdGFibGVzXG5cdCAgICAgICAgICAgIHZhciB0ID0gKHg4ICogMHgxMDEwMTAxKSBeICh4NCAqIDB4MTAwMDEpIF4gKHgyICogMHgxMDEpIF4gKHggKiAweDEwMTAxMDApO1xuXHQgICAgICAgICAgICBJTlZfU1VCX01JWF8wW3N4XSA9ICh0IDw8IDI0KSB8ICh0ID4+PiA4KTtcblx0ICAgICAgICAgICAgSU5WX1NVQl9NSVhfMVtzeF0gPSAodCA8PCAxNikgfCAodCA+Pj4gMTYpO1xuXHQgICAgICAgICAgICBJTlZfU1VCX01JWF8yW3N4XSA9ICh0IDw8IDgpICB8ICh0ID4+PiAyNCk7XG5cdCAgICAgICAgICAgIElOVl9TVUJfTUlYXzNbc3hdID0gdDtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRlIG5leHQgY291bnRlclxuXHQgICAgICAgICAgICBpZiAoIXgpIHtcblx0ICAgICAgICAgICAgICAgIHggPSB4aSA9IDE7XG5cdCAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICB4ID0geDIgXiBkW2RbZFt4OCBeIHgyXV1dO1xuXHQgICAgICAgICAgICAgICAgeGkgXj0gZFtkW3hpXV07XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9XG5cdCAgICB9KCkpO1xuXG5cdCAgICAvLyBQcmVjb21wdXRlZCBSY29uIGxvb2t1cFxuXHQgICAgdmFyIFJDT04gPSBbMHgwMCwgMHgwMSwgMHgwMiwgMHgwNCwgMHgwOCwgMHgxMCwgMHgyMCwgMHg0MCwgMHg4MCwgMHgxYiwgMHgzNl07XG5cblx0ICAgIC8qKlxuXHQgICAgICogQUVTIGJsb2NrIGNpcGhlciBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBBRVMgPSBDX2FsZ28uQUVTID0gQmxvY2tDaXBoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTa2lwIHJlc2V0IG9mIG5Sb3VuZHMgaGFzIGJlZW4gc2V0IGJlZm9yZSBhbmQga2V5IGRpZCBub3QgY2hhbmdlXG5cdCAgICAgICAgICAgIGlmICh0aGlzLl9uUm91bmRzICYmIHRoaXMuX2tleVByaW9yUmVzZXQgPT09IHRoaXMuX2tleSkge1xuXHQgICAgICAgICAgICAgICAgcmV0dXJuO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBrZXkgPSB0aGlzLl9rZXlQcmlvclJlc2V0ID0gdGhpcy5fa2V5O1xuXHQgICAgICAgICAgICB2YXIga2V5V29yZHMgPSBrZXkud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBrZXlTaXplID0ga2V5LnNpZ0J5dGVzIC8gNDtcblxuXHQgICAgICAgICAgICAvLyBDb21wdXRlIG51bWJlciBvZiByb3VuZHNcblx0ICAgICAgICAgICAgdmFyIG5Sb3VuZHMgPSB0aGlzLl9uUm91bmRzID0ga2V5U2l6ZSArIDY7XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBudW1iZXIgb2Yga2V5IHNjaGVkdWxlIHJvd3Ncblx0ICAgICAgICAgICAgdmFyIGtzUm93cyA9IChuUm91bmRzICsgMSkgKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUga2V5IHNjaGVkdWxlXG5cdCAgICAgICAgICAgIHZhciBrZXlTY2hlZHVsZSA9IHRoaXMuX2tleVNjaGVkdWxlID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGtzUm93ID0gMDsga3NSb3cgPCBrc1Jvd3M7IGtzUm93KyspIHtcblx0ICAgICAgICAgICAgICAgIGlmIChrc1JvdyA8IGtleVNpemUpIHtcblx0ICAgICAgICAgICAgICAgICAgICBrZXlTY2hlZHVsZVtrc1Jvd10gPSBrZXlXb3Jkc1trc1Jvd107XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciB0ID0ga2V5U2NoZWR1bGVba3NSb3cgLSAxXTtcblxuXHQgICAgICAgICAgICAgICAgICAgIGlmICghKGtzUm93ICUga2V5U2l6ZSkpIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgLy8gUm90IHdvcmRcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdCA9ICh0IDw8IDgpIHwgKHQgPj4+IDI0KTtcblxuXHQgICAgICAgICAgICAgICAgICAgICAgICAvLyBTdWIgd29yZFxuXHQgICAgICAgICAgICAgICAgICAgICAgICB0ID0gKFNCT1hbdCA+Pj4gMjRdIDw8IDI0KSB8IChTQk9YWyh0ID4+PiAxNikgJiAweGZmXSA8PCAxNikgfCAoU0JPWFsodCA+Pj4gOCkgJiAweGZmXSA8PCA4KSB8IFNCT1hbdCAmIDB4ZmZdO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgICAgIC8vIE1peCBSY29uXG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHQgXj0gUkNPTlsoa3NSb3cgLyBrZXlTaXplKSB8IDBdIDw8IDI0O1xuXHQgICAgICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoa2V5U2l6ZSA+IDYgJiYga3NSb3cgJSBrZXlTaXplID09IDQpIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgLy8gU3ViIHdvcmRcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdCA9IChTQk9YW3QgPj4+IDI0XSA8PCAyNCkgfCAoU0JPWFsodCA+Pj4gMTYpICYgMHhmZl0gPDwgMTYpIHwgKFNCT1hbKHQgPj4+IDgpICYgMHhmZl0gPDwgOCkgfCBTQk9YW3QgJiAweGZmXTtcblx0ICAgICAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgICAgICBrZXlTY2hlZHVsZVtrc1Jvd10gPSBrZXlTY2hlZHVsZVtrc1JvdyAtIGtleVNpemVdIF4gdDtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGUgaW52IGtleSBzY2hlZHVsZVxuXHQgICAgICAgICAgICB2YXIgaW52S2V5U2NoZWR1bGUgPSB0aGlzLl9pbnZLZXlTY2hlZHVsZSA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpbnZLc1JvdyA9IDA7IGludktzUm93IDwga3NSb3dzOyBpbnZLc1JvdysrKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIga3NSb3cgPSBrc1Jvd3MgLSBpbnZLc1JvdztcblxuXHQgICAgICAgICAgICAgICAgaWYgKGludktzUm93ICUgNCkge1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciB0ID0ga2V5U2NoZWR1bGVba3NSb3ddO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgdCA9IGtleVNjaGVkdWxlW2tzUm93IC0gNF07XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIGlmIChpbnZLc1JvdyA8IDQgfHwga3NSb3cgPD0gNCkge1xuXHQgICAgICAgICAgICAgICAgICAgIGludktleVNjaGVkdWxlW2ludktzUm93XSA9IHQ7XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgICAgIGludktleVNjaGVkdWxlW2ludktzUm93XSA9IElOVl9TVUJfTUlYXzBbU0JPWFt0ID4+PiAyNF1dIF4gSU5WX1NVQl9NSVhfMVtTQk9YWyh0ID4+PiAxNikgJiAweGZmXV0gXlxuXHQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIElOVl9TVUJfTUlYXzJbU0JPWFsodCA+Pj4gOCkgJiAweGZmXV0gXiBJTlZfU1VCX01JWF8zW1NCT1hbdCAmIDB4ZmZdXTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBlbmNyeXB0QmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgdGhpcy5fZG9DcnlwdEJsb2NrKE0sIG9mZnNldCwgdGhpcy5fa2V5U2NoZWR1bGUsIFNVQl9NSVhfMCwgU1VCX01JWF8xLCBTVUJfTUlYXzIsIFNVQl9NSVhfMywgU0JPWCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGRlY3J5cHRCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTd2FwIDJuZCBhbmQgNHRoIHJvd3Ncblx0ICAgICAgICAgICAgdmFyIHQgPSBNW29mZnNldCArIDFdO1xuXHQgICAgICAgICAgICBNW29mZnNldCArIDFdID0gTVtvZmZzZXQgKyAzXTtcblx0ICAgICAgICAgICAgTVtvZmZzZXQgKyAzXSA9IHQ7XG5cblx0ICAgICAgICAgICAgdGhpcy5fZG9DcnlwdEJsb2NrKE0sIG9mZnNldCwgdGhpcy5faW52S2V5U2NoZWR1bGUsIElOVl9TVUJfTUlYXzAsIElOVl9TVUJfTUlYXzEsIElOVl9TVUJfTUlYXzIsIElOVl9TVUJfTUlYXzMsIElOVl9TQk9YKTtcblxuXHQgICAgICAgICAgICAvLyBJbnYgc3dhcCAybmQgYW5kIDR0aCByb3dzXG5cdCAgICAgICAgICAgIHZhciB0ID0gTVtvZmZzZXQgKyAxXTtcblx0ICAgICAgICAgICAgTVtvZmZzZXQgKyAxXSA9IE1bb2Zmc2V0ICsgM107XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0ICsgM10gPSB0O1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9DcnlwdEJsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0LCBrZXlTY2hlZHVsZSwgU1VCX01JWF8wLCBTVUJfTUlYXzEsIFNVQl9NSVhfMiwgU1VCX01JWF8zLCBTQk9YKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBuUm91bmRzID0gdGhpcy5fblJvdW5kcztcblxuXHQgICAgICAgICAgICAvLyBHZXQgaW5wdXQsIGFkZCByb3VuZCBrZXlcblx0ICAgICAgICAgICAgdmFyIHMwID0gTVtvZmZzZXRdICAgICBeIGtleVNjaGVkdWxlWzBdO1xuXHQgICAgICAgICAgICB2YXIgczEgPSBNW29mZnNldCArIDFdIF4ga2V5U2NoZWR1bGVbMV07XG5cdCAgICAgICAgICAgIHZhciBzMiA9IE1bb2Zmc2V0ICsgMl0gXiBrZXlTY2hlZHVsZVsyXTtcblx0ICAgICAgICAgICAgdmFyIHMzID0gTVtvZmZzZXQgKyAzXSBeIGtleVNjaGVkdWxlWzNdO1xuXG5cdCAgICAgICAgICAgIC8vIEtleSBzY2hlZHVsZSByb3cgY291bnRlclxuXHQgICAgICAgICAgICB2YXIga3NSb3cgPSA0O1xuXG5cdCAgICAgICAgICAgIC8vIFJvdW5kc1xuXHQgICAgICAgICAgICBmb3IgKHZhciByb3VuZCA9IDE7IHJvdW5kIDwgblJvdW5kczsgcm91bmQrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hpZnQgcm93cywgc3ViIGJ5dGVzLCBtaXggY29sdW1ucywgYWRkIHJvdW5kIGtleVxuXHQgICAgICAgICAgICAgICAgdmFyIHQwID0gU1VCX01JWF8wW3MwID4+PiAyNF0gXiBTVUJfTUlYXzFbKHMxID4+PiAxNikgJiAweGZmXSBeIFNVQl9NSVhfMlsoczIgPj4+IDgpICYgMHhmZl0gXiBTVUJfTUlYXzNbczMgJiAweGZmXSBeIGtleVNjaGVkdWxlW2tzUm93KytdO1xuXHQgICAgICAgICAgICAgICAgdmFyIHQxID0gU1VCX01JWF8wW3MxID4+PiAyNF0gXiBTVUJfTUlYXzFbKHMyID4+PiAxNikgJiAweGZmXSBeIFNVQl9NSVhfMlsoczMgPj4+IDgpICYgMHhmZl0gXiBTVUJfTUlYXzNbczAgJiAweGZmXSBeIGtleVNjaGVkdWxlW2tzUm93KytdO1xuXHQgICAgICAgICAgICAgICAgdmFyIHQyID0gU1VCX01JWF8wW3MyID4+PiAyNF0gXiBTVUJfTUlYXzFbKHMzID4+PiAxNikgJiAweGZmXSBeIFNVQl9NSVhfMlsoczAgPj4+IDgpICYgMHhmZl0gXiBTVUJfTUlYXzNbczEgJiAweGZmXSBeIGtleVNjaGVkdWxlW2tzUm93KytdO1xuXHQgICAgICAgICAgICAgICAgdmFyIHQzID0gU1VCX01JWF8wW3MzID4+PiAyNF0gXiBTVUJfTUlYXzFbKHMwID4+PiAxNikgJiAweGZmXSBeIFNVQl9NSVhfMlsoczEgPj4+IDgpICYgMHhmZl0gXiBTVUJfTUlYXzNbczIgJiAweGZmXSBeIGtleVNjaGVkdWxlW2tzUm93KytdO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBVcGRhdGUgc3RhdGVcblx0ICAgICAgICAgICAgICAgIHMwID0gdDA7XG5cdCAgICAgICAgICAgICAgICBzMSA9IHQxO1xuXHQgICAgICAgICAgICAgICAgczIgPSB0Mjtcblx0ICAgICAgICAgICAgICAgIHMzID0gdDM7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBTaGlmdCByb3dzLCBzdWIgYnl0ZXMsIGFkZCByb3VuZCBrZXlcblx0ICAgICAgICAgICAgdmFyIHQwID0gKChTQk9YW3MwID4+PiAyNF0gPDwgMjQpIHwgKFNCT1hbKHMxID4+PiAxNikgJiAweGZmXSA8PCAxNikgfCAoU0JPWFsoczIgPj4+IDgpICYgMHhmZl0gPDwgOCkgfCBTQk9YW3MzICYgMHhmZl0pIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cdCAgICAgICAgICAgIHZhciB0MSA9ICgoU0JPWFtzMSA+Pj4gMjRdIDw8IDI0KSB8IChTQk9YWyhzMiA+Pj4gMTYpICYgMHhmZl0gPDwgMTYpIHwgKFNCT1hbKHMzID4+PiA4KSAmIDB4ZmZdIDw8IDgpIHwgU0JPWFtzMCAmIDB4ZmZdKSBeIGtleVNjaGVkdWxlW2tzUm93KytdO1xuXHQgICAgICAgICAgICB2YXIgdDIgPSAoKFNCT1hbczIgPj4+IDI0XSA8PCAyNCkgfCAoU0JPWFsoczMgPj4+IDE2KSAmIDB4ZmZdIDw8IDE2KSB8IChTQk9YWyhzMCA+Pj4gOCkgJiAweGZmXSA8PCA4KSB8IFNCT1hbczEgJiAweGZmXSkgXiBrZXlTY2hlZHVsZVtrc1JvdysrXTtcblx0ICAgICAgICAgICAgdmFyIHQzID0gKChTQk9YW3MzID4+PiAyNF0gPDwgMjQpIHwgKFNCT1hbKHMwID4+PiAxNikgJiAweGZmXSA8PCAxNikgfCAoU0JPWFsoczEgPj4+IDgpICYgMHhmZl0gPDwgOCkgfCBTQk9YW3MyICYgMHhmZl0pIF4ga2V5U2NoZWR1bGVba3NSb3crK107XG5cblx0ICAgICAgICAgICAgLy8gU2V0IG91dHB1dFxuXHQgICAgICAgICAgICBNW29mZnNldF0gICAgID0gdDA7XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0ICsgMV0gPSB0MTtcblx0ICAgICAgICAgICAgTVtvZmZzZXQgKyAyXSA9IHQyO1xuXHQgICAgICAgICAgICBNW29mZnNldCArIDNdID0gdDM7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGtleVNpemU6IDI1Ni8zMlxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb25zIHRvIHRoZSBjaXBoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0ID0gQ3J5cHRvSlMuQUVTLmVuY3J5cHQobWVzc2FnZSwga2V5LCBjZmcpO1xuXHQgICAgICogICAgIHZhciBwbGFpbnRleHQgID0gQ3J5cHRvSlMuQUVTLmRlY3J5cHQoY2lwaGVydGV4dCwga2V5LCBjZmcpO1xuXHQgICAgICovXG5cdCAgICBDLkFFUyA9IEJsb2NrQ2lwaGVyLl9jcmVhdGVIZWxwZXIoQUVTKTtcblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5BRVM7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vZXZwa2RmXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2V2cGtkZlwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0LyoqXG5cdCAqIENpcGhlciBjb3JlIGNvbXBvbmVudHMuXG5cdCAqL1xuXHRDcnlwdG9KUy5saWIuQ2lwaGVyIHx8IChmdW5jdGlvbiAodW5kZWZpbmVkKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBCYXNlID0gQ19saWIuQmFzZTtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgQnVmZmVyZWRCbG9ja0FsZ29yaXRobSA9IENfbGliLkJ1ZmZlcmVkQmxvY2tBbGdvcml0aG07XG5cdCAgICB2YXIgQ19lbmMgPSBDLmVuYztcblx0ICAgIHZhciBVdGY4ID0gQ19lbmMuVXRmODtcblx0ICAgIHZhciBCYXNlNjQgPSBDX2VuYy5CYXNlNjQ7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXHQgICAgdmFyIEV2cEtERiA9IENfYWxnby5FdnBLREY7XG5cblx0ICAgIC8qKlxuXHQgICAgICogQWJzdHJhY3QgYmFzZSBjaXBoZXIgdGVtcGxhdGUuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IGtleVNpemUgVGhpcyBjaXBoZXIncyBrZXkgc2l6ZS4gRGVmYXVsdDogNCAoMTI4IGJpdHMpXG5cdCAgICAgKiBAcHJvcGVydHkge251bWJlcn0gaXZTaXplIFRoaXMgY2lwaGVyJ3MgSVYgc2l6ZS4gRGVmYXVsdDogNCAoMTI4IGJpdHMpXG5cdCAgICAgKiBAcHJvcGVydHkge251bWJlcn0gX0VOQ19YRk9STV9NT0RFIEEgY29uc3RhbnQgcmVwcmVzZW50aW5nIGVuY3J5cHRpb24gbW9kZS5cblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBfREVDX1hGT1JNX01PREUgQSBjb25zdGFudCByZXByZXNlbnRpbmcgZGVjcnlwdGlvbiBtb2RlLlxuXHQgICAgICovXG5cdCAgICB2YXIgQ2lwaGVyID0gQ19saWIuQ2lwaGVyID0gQnVmZmVyZWRCbG9ja0FsZ29yaXRobS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmZpZ3VyYXRpb24gb3B0aW9ucy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7V29yZEFycmF5fSBpdiBUaGUgSVYgdG8gdXNlIGZvciB0aGlzIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjZmc6IEJhc2UuZXh0ZW5kKCksXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDcmVhdGVzIHRoaXMgY2lwaGVyIGluIGVuY3J5cHRpb24gbW9kZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSBrZXkgVGhlIGtleS5cblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoaXMgb3BlcmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7Q2lwaGVyfSBBIGNpcGhlciBpbnN0YW5jZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlciA9IENyeXB0b0pTLmFsZ28uQUVTLmNyZWF0ZUVuY3J5cHRvcihrZXlXb3JkQXJyYXksIHsgaXY6IGl2V29yZEFycmF5IH0pO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNyZWF0ZUVuY3J5cHRvcjogZnVuY3Rpb24gKGtleSwgY2ZnKSB7XG5cdCAgICAgICAgICAgIHJldHVybiB0aGlzLmNyZWF0ZSh0aGlzLl9FTkNfWEZPUk1fTU9ERSwga2V5LCBjZmcpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDcmVhdGVzIHRoaXMgY2lwaGVyIGluIGRlY3J5cHRpb24gbW9kZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSBrZXkgVGhlIGtleS5cblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoaXMgb3BlcmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7Q2lwaGVyfSBBIGNpcGhlciBpbnN0YW5jZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlciA9IENyeXB0b0pTLmFsZ28uQUVTLmNyZWF0ZURlY3J5cHRvcihrZXlXb3JkQXJyYXksIHsgaXY6IGl2V29yZEFycmF5IH0pO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNyZWF0ZURlY3J5cHRvcjogZnVuY3Rpb24gKGtleSwgY2ZnKSB7XG5cdCAgICAgICAgICAgIHJldHVybiB0aGlzLmNyZWF0ZSh0aGlzLl9ERUNfWEZPUk1fTU9ERSwga2V5LCBjZmcpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQgY2lwaGVyLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IHhmb3JtTW9kZSBFaXRoZXIgdGhlIGVuY3J5cHRpb24gb3IgZGVjcnlwdGlvbiB0cmFuc29ybWF0aW9uIG1vZGUgY29uc3RhbnQuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGtleSBUaGUga2V5LlxuXHQgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjaXBoZXIgPSBDcnlwdG9KUy5hbGdvLkFFUy5jcmVhdGUoQ3J5cHRvSlMuYWxnby5BRVMuX0VOQ19YRk9STV9NT0RFLCBrZXlXb3JkQXJyYXksIHsgaXY6IGl2V29yZEFycmF5IH0pO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGluaXQ6IGZ1bmN0aW9uICh4Zm9ybU1vZGUsIGtleSwgY2ZnKSB7XG5cdCAgICAgICAgICAgIC8vIEFwcGx5IGNvbmZpZyBkZWZhdWx0c1xuXHQgICAgICAgICAgICB0aGlzLmNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXG5cdCAgICAgICAgICAgIC8vIFN0b3JlIHRyYW5zZm9ybSBtb2RlIGFuZCBrZXlcblx0ICAgICAgICAgICAgdGhpcy5feGZvcm1Nb2RlID0geGZvcm1Nb2RlO1xuXHQgICAgICAgICAgICB0aGlzLl9rZXkgPSBrZXk7XG5cblx0ICAgICAgICAgICAgLy8gU2V0IGluaXRpYWwgdmFsdWVzXG5cdCAgICAgICAgICAgIHRoaXMucmVzZXQoKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogUmVzZXRzIHRoaXMgY2lwaGVyIHRvIGl0cyBpbml0aWFsIHN0YXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBjaXBoZXIucmVzZXQoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICByZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBSZXNldCBkYXRhIGJ1ZmZlclxuXHQgICAgICAgICAgICBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtLnJlc2V0LmNhbGwodGhpcyk7XG5cblx0ICAgICAgICAgICAgLy8gUGVyZm9ybSBjb25jcmV0ZS1jaXBoZXIgbG9naWNcblx0ICAgICAgICAgICAgdGhpcy5fZG9SZXNldCgpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBBZGRzIGRhdGEgdG8gYmUgZW5jcnlwdGVkIG9yIGRlY3J5cHRlZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gZGF0YVVwZGF0ZSBUaGUgZGF0YSB0byBlbmNyeXB0IG9yIGRlY3J5cHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBkYXRhIGFmdGVyIHByb2Nlc3NpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBlbmNyeXB0ZWQgPSBjaXBoZXIucHJvY2VzcygnZGF0YScpO1xuXHQgICAgICAgICAqICAgICB2YXIgZW5jcnlwdGVkID0gY2lwaGVyLnByb2Nlc3Mod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBwcm9jZXNzOiBmdW5jdGlvbiAoZGF0YVVwZGF0ZSkge1xuXHQgICAgICAgICAgICAvLyBBcHBlbmRcblx0ICAgICAgICAgICAgdGhpcy5fYXBwZW5kKGRhdGFVcGRhdGUpO1xuXG5cdCAgICAgICAgICAgIC8vIFByb2Nlc3MgYXZhaWxhYmxlIGJsb2Nrc1xuXHQgICAgICAgICAgICByZXR1cm4gdGhpcy5fcHJvY2VzcygpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBGaW5hbGl6ZXMgdGhlIGVuY3J5cHRpb24gb3IgZGVjcnlwdGlvbiBwcm9jZXNzLlxuXHQgICAgICAgICAqIE5vdGUgdGhhdCB0aGUgZmluYWxpemUgb3BlcmF0aW9uIGlzIGVmZmVjdGl2ZWx5IGEgZGVzdHJ1Y3RpdmUsIHJlYWQtb25jZSBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IGRhdGFVcGRhdGUgVGhlIGZpbmFsIGRhdGEgdG8gZW5jcnlwdCBvciBkZWNyeXB0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgZGF0YSBhZnRlciBmaW5hbCBwcm9jZXNzaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgZW5jcnlwdGVkID0gY2lwaGVyLmZpbmFsaXplKCk7XG5cdCAgICAgICAgICogICAgIHZhciBlbmNyeXB0ZWQgPSBjaXBoZXIuZmluYWxpemUoJ2RhdGEnKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGVuY3J5cHRlZCA9IGNpcGhlci5maW5hbGl6ZSh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGZpbmFsaXplOiBmdW5jdGlvbiAoZGF0YVVwZGF0ZSkge1xuXHQgICAgICAgICAgICAvLyBGaW5hbCBkYXRhIHVwZGF0ZVxuXHQgICAgICAgICAgICBpZiAoZGF0YVVwZGF0ZSkge1xuXHQgICAgICAgICAgICAgICAgdGhpcy5fYXBwZW5kKGRhdGFVcGRhdGUpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gUGVyZm9ybSBjb25jcmV0ZS1jaXBoZXIgbG9naWNcblx0ICAgICAgICAgICAgdmFyIGZpbmFsUHJvY2Vzc2VkRGF0YSA9IHRoaXMuX2RvRmluYWxpemUoKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gZmluYWxQcm9jZXNzZWREYXRhO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBrZXlTaXplOiAxMjgvMzIsXG5cblx0ICAgICAgICBpdlNpemU6IDEyOC8zMixcblxuXHQgICAgICAgIF9FTkNfWEZPUk1fTU9ERTogMSxcblxuXHQgICAgICAgIF9ERUNfWEZPUk1fTU9ERTogMixcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgc2hvcnRjdXQgZnVuY3Rpb25zIHRvIGEgY2lwaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyfSBjaXBoZXIgVGhlIGNpcGhlciB0byBjcmVhdGUgYSBoZWxwZXIgZm9yLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7T2JqZWN0fSBBbiBvYmplY3Qgd2l0aCBlbmNyeXB0IGFuZCBkZWNyeXB0IHNob3J0Y3V0IGZ1bmN0aW9ucy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIEFFUyA9IENyeXB0b0pTLmxpYi5DaXBoZXIuX2NyZWF0ZUhlbHBlcihDcnlwdG9KUy5hbGdvLkFFUyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgX2NyZWF0ZUhlbHBlcjogKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgZnVuY3Rpb24gc2VsZWN0Q2lwaGVyU3RyYXRlZ3koa2V5KSB7XG5cdCAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGtleSA9PSAnc3RyaW5nJykge1xuXHQgICAgICAgICAgICAgICAgICAgIHJldHVybiBQYXNzd29yZEJhc2VkQ2lwaGVyO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgICAgICByZXR1cm4gU2VyaWFsaXphYmxlQ2lwaGVyO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChjaXBoZXIpIHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiB7XG5cdCAgICAgICAgICAgICAgICAgICAgZW5jcnlwdDogZnVuY3Rpb24gKG1lc3NhZ2UsIGtleSwgY2ZnKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBzZWxlY3RDaXBoZXJTdHJhdGVneShrZXkpLmVuY3J5cHQoY2lwaGVyLCBtZXNzYWdlLCBrZXksIGNmZyk7XG5cdCAgICAgICAgICAgICAgICAgICAgfSxcblxuXHQgICAgICAgICAgICAgICAgICAgIGRlY3J5cHQ6IGZ1bmN0aW9uIChjaXBoZXJ0ZXh0LCBrZXksIGNmZykge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICByZXR1cm4gc2VsZWN0Q2lwaGVyU3RyYXRlZ3koa2V5KS5kZWNyeXB0KGNpcGhlciwgY2lwaGVydGV4dCwga2V5LCBjZmcpO1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIH07XG5cdCAgICAgICAgICAgIH07XG5cdCAgICAgICAgfSgpKVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogQWJzdHJhY3QgYmFzZSBzdHJlYW0gY2lwaGVyIHRlbXBsYXRlLlxuXHQgICAgICpcblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBibG9ja1NpemUgVGhlIG51bWJlciBvZiAzMi1iaXQgd29yZHMgdGhpcyBjaXBoZXIgb3BlcmF0ZXMgb24uIERlZmF1bHQ6IDEgKDMyIGJpdHMpXG5cdCAgICAgKi9cblx0ICAgIHZhciBTdHJlYW1DaXBoZXIgPSBDX2xpYi5TdHJlYW1DaXBoZXIgPSBDaXBoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9GaW5hbGl6ZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBQcm9jZXNzIHBhcnRpYWwgYmxvY2tzXG5cdCAgICAgICAgICAgIHZhciBmaW5hbFByb2Nlc3NlZEJsb2NrcyA9IHRoaXMuX3Byb2Nlc3MoISEnZmx1c2gnKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gZmluYWxQcm9jZXNzZWRCbG9ja3M7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGJsb2NrU2l6ZTogMVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogTW9kZSBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX21vZGUgPSBDLm1vZGUgPSB7fTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBYnN0cmFjdCBiYXNlIGJsb2NrIGNpcGhlciBtb2RlIHRlbXBsYXRlLlxuXHQgICAgICovXG5cdCAgICB2YXIgQmxvY2tDaXBoZXJNb2RlID0gQ19saWIuQmxvY2tDaXBoZXJNb2RlID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgdGhpcyBtb2RlIGZvciBlbmNyeXB0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBBIGJsb2NrIGNpcGhlciBpbnN0YW5jZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge0FycmF5fSBpdiBUaGUgSVYgd29yZHMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBtb2RlID0gQ3J5cHRvSlMubW9kZS5DQkMuY3JlYXRlRW5jcnlwdG9yKGNpcGhlciwgaXYud29yZHMpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNyZWF0ZUVuY3J5cHRvcjogZnVuY3Rpb24gKGNpcGhlciwgaXYpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXMuRW5jcnlwdG9yLmNyZWF0ZShjaXBoZXIsIGl2KTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ3JlYXRlcyB0aGlzIG1vZGUgZm9yIGRlY3J5cHRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0NpcGhlcn0gY2lwaGVyIEEgYmxvY2sgY2lwaGVyIGluc3RhbmNlLlxuXHQgICAgICAgICAqIEBwYXJhbSB7QXJyYXl9IGl2IFRoZSBJViB3b3Jkcy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIG1vZGUgPSBDcnlwdG9KUy5tb2RlLkNCQy5jcmVhdGVEZWNyeXB0b3IoY2lwaGVyLCBpdi53b3Jkcyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY3JlYXRlRGVjcnlwdG9yOiBmdW5jdGlvbiAoY2lwaGVyLCBpdikge1xuXHQgICAgICAgICAgICByZXR1cm4gdGhpcy5EZWNyeXB0b3IuY3JlYXRlKGNpcGhlciwgaXYpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQgbW9kZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyfSBjaXBoZXIgQSBibG9jayBjaXBoZXIgaW5zdGFuY2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtBcnJheX0gaXYgVGhlIElWIHdvcmRzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgbW9kZSA9IENyeXB0b0pTLm1vZGUuQ0JDLkVuY3J5cHRvci5jcmVhdGUoY2lwaGVyLCBpdi53b3Jkcyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKGNpcGhlciwgaXYpIHtcblx0ICAgICAgICAgICAgdGhpcy5fY2lwaGVyID0gY2lwaGVyO1xuXHQgICAgICAgICAgICB0aGlzLl9pdiA9IGl2O1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIENpcGhlciBCbG9jayBDaGFpbmluZyBtb2RlLlxuXHQgICAgICovXG5cdCAgICB2YXIgQ0JDID0gQ19tb2RlLkNCQyA9IChmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQWJzdHJhY3QgYmFzZSBDQkMgbW9kZS5cblx0ICAgICAgICAgKi9cblx0ICAgICAgICB2YXIgQ0JDID0gQmxvY2tDaXBoZXJNb2RlLmV4dGVuZCgpO1xuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ0JDIGVuY3J5cHRvci5cblx0ICAgICAgICAgKi9cblx0ICAgICAgICBDQkMuRW5jcnlwdG9yID0gQ0JDLmV4dGVuZCh7XG5cdCAgICAgICAgICAgIC8qKlxuXHQgICAgICAgICAgICAgKiBQcm9jZXNzZXMgdGhlIGRhdGEgYmxvY2sgYXQgb2Zmc2V0LlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAcGFyYW0ge0FycmF5fSB3b3JkcyBUaGUgZGF0YSB3b3JkcyB0byBvcGVyYXRlIG9uLlxuXHQgICAgICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0gb2Zmc2V0IFRoZSBvZmZzZXQgd2hlcmUgdGhlIGJsb2NrIHN0YXJ0cy5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogICAgIG1vZGUucHJvY2Vzc0Jsb2NrKGRhdGEud29yZHMsIG9mZnNldCk7XG5cdCAgICAgICAgICAgICAqL1xuXHQgICAgICAgICAgICBwcm9jZXNzQmxvY2s6IGZ1bmN0aW9uICh3b3Jkcywgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgIHZhciBjaXBoZXIgPSB0aGlzLl9jaXBoZXI7XG5cdCAgICAgICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gY2lwaGVyLmJsb2NrU2l6ZTtcblxuXHQgICAgICAgICAgICAgICAgLy8gWE9SIGFuZCBlbmNyeXB0XG5cdCAgICAgICAgICAgICAgICB4b3JCbG9jay5jYWxsKHRoaXMsIHdvcmRzLCBvZmZzZXQsIGJsb2NrU2l6ZSk7XG5cdCAgICAgICAgICAgICAgICBjaXBoZXIuZW5jcnlwdEJsb2NrKHdvcmRzLCBvZmZzZXQpO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBSZW1lbWJlciB0aGlzIGJsb2NrIHRvIHVzZSB3aXRoIG5leHQgYmxvY2tcblx0ICAgICAgICAgICAgICAgIHRoaXMuX3ByZXZCbG9jayA9IHdvcmRzLnNsaWNlKG9mZnNldCwgb2Zmc2V0ICsgYmxvY2tTaXplKTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0pO1xuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ0JDIGRlY3J5cHRvci5cblx0ICAgICAgICAgKi9cblx0ICAgICAgICBDQkMuRGVjcnlwdG9yID0gQ0JDLmV4dGVuZCh7XG5cdCAgICAgICAgICAgIC8qKlxuXHQgICAgICAgICAgICAgKiBQcm9jZXNzZXMgdGhlIGRhdGEgYmxvY2sgYXQgb2Zmc2V0LlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAcGFyYW0ge0FycmF5fSB3b3JkcyBUaGUgZGF0YSB3b3JkcyB0byBvcGVyYXRlIG9uLlxuXHQgICAgICAgICAgICAgKiBAcGFyYW0ge251bWJlcn0gb2Zmc2V0IFRoZSBvZmZzZXQgd2hlcmUgdGhlIGJsb2NrIHN0YXJ0cy5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogICAgIG1vZGUucHJvY2Vzc0Jsb2NrKGRhdGEud29yZHMsIG9mZnNldCk7XG5cdCAgICAgICAgICAgICAqL1xuXHQgICAgICAgICAgICBwcm9jZXNzQmxvY2s6IGZ1bmN0aW9uICh3b3Jkcywgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgIHZhciBjaXBoZXIgPSB0aGlzLl9jaXBoZXI7XG5cdCAgICAgICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gY2lwaGVyLmJsb2NrU2l6ZTtcblxuXHQgICAgICAgICAgICAgICAgLy8gUmVtZW1iZXIgdGhpcyBibG9jayB0byB1c2Ugd2l0aCBuZXh0IGJsb2NrXG5cdCAgICAgICAgICAgICAgICB2YXIgdGhpc0Jsb2NrID0gd29yZHMuc2xpY2Uob2Zmc2V0LCBvZmZzZXQgKyBibG9ja1NpemUpO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBEZWNyeXB0IGFuZCBYT1Jcblx0ICAgICAgICAgICAgICAgIGNpcGhlci5kZWNyeXB0QmxvY2sod29yZHMsIG9mZnNldCk7XG5cdCAgICAgICAgICAgICAgICB4b3JCbG9jay5jYWxsKHRoaXMsIHdvcmRzLCBvZmZzZXQsIGJsb2NrU2l6ZSk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFRoaXMgYmxvY2sgYmVjb21lcyB0aGUgcHJldmlvdXMgYmxvY2tcblx0ICAgICAgICAgICAgICAgIHRoaXMuX3ByZXZCbG9jayA9IHRoaXNCbG9jaztcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0pO1xuXG5cdCAgICAgICAgZnVuY3Rpb24geG9yQmxvY2sod29yZHMsIG9mZnNldCwgYmxvY2tTaXplKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBpdiA9IHRoaXMuX2l2O1xuXG5cdCAgICAgICAgICAgIC8vIENob29zZSBtaXhpbmcgYmxvY2tcblx0ICAgICAgICAgICAgaWYgKGl2KSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgYmxvY2sgPSBpdjtcblxuXHQgICAgICAgICAgICAgICAgLy8gUmVtb3ZlIElWIGZvciBzdWJzZXF1ZW50IGJsb2Nrc1xuXHQgICAgICAgICAgICAgICAgdGhpcy5faXYgPSB1bmRlZmluZWQ7XG5cdCAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgYmxvY2sgPSB0aGlzLl9wcmV2QmxvY2s7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBYT1IgYmxvY2tzXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYmxvY2tTaXplOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHdvcmRzW29mZnNldCArIGldIF49IGJsb2NrW2ldO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgcmV0dXJuIENCQztcblx0ICAgIH0oKSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogUGFkZGluZyBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX3BhZCA9IEMucGFkID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogUEtDUyAjNS83IHBhZGRpbmcgc3RyYXRlZ3kuXG5cdCAgICAgKi9cblx0ICAgIHZhciBQa2NzNyA9IENfcGFkLlBrY3M3ID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFBhZHMgZGF0YSB1c2luZyB0aGUgYWxnb3JpdGhtIGRlZmluZWQgaW4gUEtDUyAjNS83LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGRhdGEgVGhlIGRhdGEgdG8gcGFkLlxuXHQgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBibG9ja1NpemUgVGhlIG11bHRpcGxlIHRoYXQgdGhlIGRhdGEgc2hvdWxkIGJlIHBhZGRlZCB0by5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgQ3J5cHRvSlMucGFkLlBrY3M3LnBhZCh3b3JkQXJyYXksIDQpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHBhZDogZnVuY3Rpb24gKGRhdGEsIGJsb2NrU2l6ZSkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgYmxvY2tTaXplQnl0ZXMgPSBibG9ja1NpemUgKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIENvdW50IHBhZGRpbmcgYnl0ZXNcblx0ICAgICAgICAgICAgdmFyIG5QYWRkaW5nQnl0ZXMgPSBibG9ja1NpemVCeXRlcyAtIGRhdGEuc2lnQnl0ZXMgJSBibG9ja1NpemVCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDcmVhdGUgcGFkZGluZyB3b3JkXG5cdCAgICAgICAgICAgIHZhciBwYWRkaW5nV29yZCA9IChuUGFkZGluZ0J5dGVzIDw8IDI0KSB8IChuUGFkZGluZ0J5dGVzIDw8IDE2KSB8IChuUGFkZGluZ0J5dGVzIDw8IDgpIHwgblBhZGRpbmdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDcmVhdGUgcGFkZGluZ1xuXHQgICAgICAgICAgICB2YXIgcGFkZGluZ1dvcmRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgblBhZGRpbmdCeXRlczsgaSArPSA0KSB7XG5cdCAgICAgICAgICAgICAgICBwYWRkaW5nV29yZHMucHVzaChwYWRkaW5nV29yZCk7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgdmFyIHBhZGRpbmcgPSBXb3JkQXJyYXkuY3JlYXRlKHBhZGRpbmdXb3JkcywgblBhZGRpbmdCeXRlcyk7XG5cblx0ICAgICAgICAgICAgLy8gQWRkIHBhZGRpbmdcblx0ICAgICAgICAgICAgZGF0YS5jb25jYXQocGFkZGluZyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFVucGFkcyBkYXRhIHRoYXQgaGFkIGJlZW4gcGFkZGVkIHVzaW5nIHRoZSBhbGdvcml0aG0gZGVmaW5lZCBpbiBQS0NTICM1LzcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gZGF0YSBUaGUgZGF0YSB0byB1bnBhZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgQ3J5cHRvSlMucGFkLlBrY3M3LnVucGFkKHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgdW5wYWQ6IGZ1bmN0aW9uIChkYXRhKSB7XG5cdCAgICAgICAgICAgIC8vIEdldCBudW1iZXIgb2YgcGFkZGluZyBieXRlcyBmcm9tIGxhc3QgYnl0ZVxuXHQgICAgICAgICAgICB2YXIgblBhZGRpbmdCeXRlcyA9IGRhdGEud29yZHNbKGRhdGEuc2lnQnl0ZXMgLSAxKSA+Pj4gMl0gJiAweGZmO1xuXG5cdCAgICAgICAgICAgIC8vIFJlbW92ZSBwYWRkaW5nXG5cdCAgICAgICAgICAgIGRhdGEuc2lnQnl0ZXMgLT0gblBhZGRpbmdCeXRlcztcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFic3RyYWN0IGJhc2UgYmxvY2sgY2lwaGVyIHRlbXBsYXRlLlxuXHQgICAgICpcblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBibG9ja1NpemUgVGhlIG51bWJlciBvZiAzMi1iaXQgd29yZHMgdGhpcyBjaXBoZXIgb3BlcmF0ZXMgb24uIERlZmF1bHQ6IDQgKDEyOCBiaXRzKVxuXHQgICAgICovXG5cdCAgICB2YXIgQmxvY2tDaXBoZXIgPSBDX2xpYi5CbG9ja0NpcGhlciA9IENpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmZpZ3VyYXRpb24gb3B0aW9ucy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7TW9kZX0gbW9kZSBUaGUgYmxvY2sgbW9kZSB0byB1c2UuIERlZmF1bHQ6IENCQ1xuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7UGFkZGluZ30gcGFkZGluZyBUaGUgcGFkZGluZyBzdHJhdGVneSB0byB1c2UuIERlZmF1bHQ6IFBrY3M3XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2ZnOiBDaXBoZXIuY2ZnLmV4dGVuZCh7XG5cdCAgICAgICAgICAgIG1vZGU6IENCQyxcblx0ICAgICAgICAgICAgcGFkZGluZzogUGtjczdcblx0ICAgICAgICB9KSxcblxuXHQgICAgICAgIHJlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFJlc2V0IGNpcGhlclxuXHQgICAgICAgICAgICBDaXBoZXIucmVzZXQuY2FsbCh0aGlzKTtcblxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGNmZyA9IHRoaXMuY2ZnO1xuXHQgICAgICAgICAgICB2YXIgaXYgPSBjZmcuaXY7XG5cdCAgICAgICAgICAgIHZhciBtb2RlID0gY2ZnLm1vZGU7XG5cblx0ICAgICAgICAgICAgLy8gUmVzZXQgYmxvY2sgbW9kZVxuXHQgICAgICAgICAgICBpZiAodGhpcy5feGZvcm1Nb2RlID09IHRoaXMuX0VOQ19YRk9STV9NT0RFKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgbW9kZUNyZWF0b3IgPSBtb2RlLmNyZWF0ZUVuY3J5cHRvcjtcblx0ICAgICAgICAgICAgfSBlbHNlIC8qIGlmICh0aGlzLl94Zm9ybU1vZGUgPT0gdGhpcy5fREVDX1hGT1JNX01PREUpICovIHtcblx0ICAgICAgICAgICAgICAgIHZhciBtb2RlQ3JlYXRvciA9IG1vZGUuY3JlYXRlRGVjcnlwdG9yO1xuXHQgICAgICAgICAgICAgICAgLy8gS2VlcCBhdCBsZWFzdCBvbmUgYmxvY2sgaW4gdGhlIGJ1ZmZlciBmb3IgdW5wYWRkaW5nXG5cdCAgICAgICAgICAgICAgICB0aGlzLl9taW5CdWZmZXJTaXplID0gMTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIGlmICh0aGlzLl9tb2RlICYmIHRoaXMuX21vZGUuX19jcmVhdG9yID09IG1vZGVDcmVhdG9yKSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9tb2RlLmluaXQodGhpcywgaXYgJiYgaXYud29yZHMpO1xuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgdGhpcy5fbW9kZSA9IG1vZGVDcmVhdG9yLmNhbGwobW9kZSwgdGhpcywgaXYgJiYgaXYud29yZHMpO1xuXHQgICAgICAgICAgICAgICAgdGhpcy5fbW9kZS5fX2NyZWF0b3IgPSBtb2RlQ3JlYXRvcjtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9Qcm9jZXNzQmxvY2s6IGZ1bmN0aW9uICh3b3Jkcywgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIHRoaXMuX21vZGUucHJvY2Vzc0Jsb2NrKHdvcmRzLCBvZmZzZXQpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9GaW5hbGl6ZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgcGFkZGluZyA9IHRoaXMuY2ZnLnBhZGRpbmc7XG5cblx0ICAgICAgICAgICAgLy8gRmluYWxpemVcblx0ICAgICAgICAgICAgaWYgKHRoaXMuX3hmb3JtTW9kZSA9PSB0aGlzLl9FTkNfWEZPUk1fTU9ERSkge1xuXHQgICAgICAgICAgICAgICAgLy8gUGFkIGRhdGFcblx0ICAgICAgICAgICAgICAgIHBhZGRpbmcucGFkKHRoaXMuX2RhdGEsIHRoaXMuYmxvY2tTaXplKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gUHJvY2VzcyBmaW5hbCBibG9ja3Ncblx0ICAgICAgICAgICAgICAgIHZhciBmaW5hbFByb2Nlc3NlZEJsb2NrcyA9IHRoaXMuX3Byb2Nlc3MoISEnZmx1c2gnKTtcblx0ICAgICAgICAgICAgfSBlbHNlIC8qIGlmICh0aGlzLl94Zm9ybU1vZGUgPT0gdGhpcy5fREVDX1hGT1JNX01PREUpICovIHtcblx0ICAgICAgICAgICAgICAgIC8vIFByb2Nlc3MgZmluYWwgYmxvY2tzXG5cdCAgICAgICAgICAgICAgICB2YXIgZmluYWxQcm9jZXNzZWRCbG9ja3MgPSB0aGlzLl9wcm9jZXNzKCEhJ2ZsdXNoJyk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFVucGFkIGRhdGFcblx0ICAgICAgICAgICAgICAgIHBhZGRpbmcudW5wYWQoZmluYWxQcm9jZXNzZWRCbG9ja3MpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGZpbmFsUHJvY2Vzc2VkQmxvY2tzO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBibG9ja1NpemU6IDEyOC8zMlxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogQSBjb2xsZWN0aW9uIG9mIGNpcGhlciBwYXJhbWV0ZXJzLlxuXHQgICAgICpcblx0ICAgICAqIEBwcm9wZXJ0eSB7V29yZEFycmF5fSBjaXBoZXJ0ZXh0IFRoZSByYXcgY2lwaGVydGV4dC5cblx0ICAgICAqIEBwcm9wZXJ0eSB7V29yZEFycmF5fSBrZXkgVGhlIGtleSB0byB0aGlzIGNpcGhlcnRleHQuXG5cdCAgICAgKiBAcHJvcGVydHkge1dvcmRBcnJheX0gaXYgVGhlIElWIHVzZWQgaW4gdGhlIGNpcGhlcmluZyBvcGVyYXRpb24uXG5cdCAgICAgKiBAcHJvcGVydHkge1dvcmRBcnJheX0gc2FsdCBUaGUgc2FsdCB1c2VkIHdpdGggYSBrZXkgZGVyaXZhdGlvbiBmdW5jdGlvbi5cblx0ICAgICAqIEBwcm9wZXJ0eSB7Q2lwaGVyfSBhbGdvcml0aG0gVGhlIGNpcGhlciBhbGdvcml0aG0uXG5cdCAgICAgKiBAcHJvcGVydHkge01vZGV9IG1vZGUgVGhlIGJsb2NrIG1vZGUgdXNlZCBpbiB0aGUgY2lwaGVyaW5nIG9wZXJhdGlvbi5cblx0ICAgICAqIEBwcm9wZXJ0eSB7UGFkZGluZ30gcGFkZGluZyBUaGUgcGFkZGluZyBzY2hlbWUgdXNlZCBpbiB0aGUgY2lwaGVyaW5nIG9wZXJhdGlvbi5cblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBibG9ja1NpemUgVGhlIGJsb2NrIHNpemUgb2YgdGhlIGNpcGhlci5cblx0ICAgICAqIEBwcm9wZXJ0eSB7Rm9ybWF0fSBmb3JtYXR0ZXIgVGhlIGRlZmF1bHQgZm9ybWF0dGluZyBzdHJhdGVneSB0byBjb252ZXJ0IHRoaXMgY2lwaGVyIHBhcmFtcyBvYmplY3QgdG8gYSBzdHJpbmcuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDaXBoZXJQYXJhbXMgPSBDX2xpYi5DaXBoZXJQYXJhbXMgPSBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogSW5pdGlhbGl6ZXMgYSBuZXdseSBjcmVhdGVkIGNpcGhlciBwYXJhbXMgb2JqZWN0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNpcGhlclBhcmFtcyBBbiBvYmplY3Qgd2l0aCBhbnkgb2YgdGhlIHBvc3NpYmxlIGNpcGhlciBwYXJhbWV0ZXJzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVyUGFyYW1zID0gQ3J5cHRvSlMubGliLkNpcGhlclBhcmFtcy5jcmVhdGUoe1xuXHQgICAgICAgICAqICAgICAgICAgY2lwaGVydGV4dDogY2lwaGVydGV4dFdvcmRBcnJheSxcblx0ICAgICAgICAgKiAgICAgICAgIGtleToga2V5V29yZEFycmF5LFxuXHQgICAgICAgICAqICAgICAgICAgaXY6IGl2V29yZEFycmF5LFxuXHQgICAgICAgICAqICAgICAgICAgc2FsdDogc2FsdFdvcmRBcnJheSxcblx0ICAgICAgICAgKiAgICAgICAgIGFsZ29yaXRobTogQ3J5cHRvSlMuYWxnby5BRVMsXG5cdCAgICAgICAgICogICAgICAgICBtb2RlOiBDcnlwdG9KUy5tb2RlLkNCQyxcblx0ICAgICAgICAgKiAgICAgICAgIHBhZGRpbmc6IENyeXB0b0pTLnBhZC5QS0NTNyxcblx0ICAgICAgICAgKiAgICAgICAgIGJsb2NrU2l6ZTogNCxcblx0ICAgICAgICAgKiAgICAgICAgIGZvcm1hdHRlcjogQ3J5cHRvSlMuZm9ybWF0Lk9wZW5TU0xcblx0ICAgICAgICAgKiAgICAgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKGNpcGhlclBhcmFtcykge1xuXHQgICAgICAgICAgICB0aGlzLm1peEluKGNpcGhlclBhcmFtcyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIHRoaXMgY2lwaGVyIHBhcmFtcyBvYmplY3QgdG8gYSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0Zvcm1hdH0gZm9ybWF0dGVyIChPcHRpb25hbCkgVGhlIGZvcm1hdHRpbmcgc3RyYXRlZ3kgdG8gdXNlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7c3RyaW5nfSBUaGUgc3RyaW5naWZpZWQgY2lwaGVyIHBhcmFtcy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEB0aHJvd3MgRXJyb3IgSWYgbmVpdGhlciB0aGUgZm9ybWF0dGVyIG5vciB0aGUgZGVmYXVsdCBmb3JtYXR0ZXIgaXMgc2V0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgc3RyaW5nID0gY2lwaGVyUGFyYW1zICsgJyc7XG5cdCAgICAgICAgICogICAgIHZhciBzdHJpbmcgPSBjaXBoZXJQYXJhbXMudG9TdHJpbmcoKTtcblx0ICAgICAgICAgKiAgICAgdmFyIHN0cmluZyA9IGNpcGhlclBhcmFtcy50b1N0cmluZyhDcnlwdG9KUy5mb3JtYXQuT3BlblNTTCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgdG9TdHJpbmc6IGZ1bmN0aW9uIChmb3JtYXR0ZXIpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIChmb3JtYXR0ZXIgfHwgdGhpcy5mb3JtYXR0ZXIpLnN0cmluZ2lmeSh0aGlzKTtcblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBGb3JtYXQgbmFtZXNwYWNlLlxuXHQgICAgICovXG5cdCAgICB2YXIgQ19mb3JtYXQgPSBDLmZvcm1hdCA9IHt9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIE9wZW5TU0wgZm9ybWF0dGluZyBzdHJhdGVneS5cblx0ICAgICAqL1xuXHQgICAgdmFyIE9wZW5TU0xGb3JtYXR0ZXIgPSBDX2Zvcm1hdC5PcGVuU1NMID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgY2lwaGVyIHBhcmFtcyBvYmplY3QgdG8gYW4gT3BlblNTTC1jb21wYXRpYmxlIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyUGFyYW1zfSBjaXBoZXJQYXJhbXMgVGhlIGNpcGhlciBwYXJhbXMgb2JqZWN0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7c3RyaW5nfSBUaGUgT3BlblNTTC1jb21wYXRpYmxlIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIG9wZW5TU0xTdHJpbmcgPSBDcnlwdG9KUy5mb3JtYXQuT3BlblNTTC5zdHJpbmdpZnkoY2lwaGVyUGFyYW1zKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBzdHJpbmdpZnk6IGZ1bmN0aW9uIChjaXBoZXJQYXJhbXMpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBjaXBoZXJ0ZXh0ID0gY2lwaGVyUGFyYW1zLmNpcGhlcnRleHQ7XG5cdCAgICAgICAgICAgIHZhciBzYWx0ID0gY2lwaGVyUGFyYW1zLnNhbHQ7XG5cblx0ICAgICAgICAgICAgLy8gRm9ybWF0XG5cdCAgICAgICAgICAgIGlmIChzYWx0KSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgd29yZEFycmF5ID0gV29yZEFycmF5LmNyZWF0ZShbMHg1MzYxNmM3NCwgMHg2NTY0NWY1Zl0pLmNvbmNhdChzYWx0KS5jb25jYXQoY2lwaGVydGV4dCk7XG5cdCAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgd29yZEFycmF5ID0gY2lwaGVydGV4dDtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiB3b3JkQXJyYXkudG9TdHJpbmcoQmFzZTY0KTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYW4gT3BlblNTTC1jb21wYXRpYmxlIHN0cmluZyB0byBhIGNpcGhlciBwYXJhbXMgb2JqZWN0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtzdHJpbmd9IG9wZW5TU0xTdHIgVGhlIE9wZW5TU0wtY29tcGF0aWJsZSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJQYXJhbXN9IFRoZSBjaXBoZXIgcGFyYW1zIG9iamVjdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlclBhcmFtcyA9IENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMLnBhcnNlKG9wZW5TU0xTdHJpbmcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHBhcnNlOiBmdW5jdGlvbiAob3BlblNTTFN0cikge1xuXHQgICAgICAgICAgICAvLyBQYXJzZSBiYXNlNjRcblx0ICAgICAgICAgICAgdmFyIGNpcGhlcnRleHQgPSBCYXNlNjQucGFyc2Uob3BlblNTTFN0cik7XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGNpcGhlcnRleHRXb3JkcyA9IGNpcGhlcnRleHQud29yZHM7XG5cblx0ICAgICAgICAgICAgLy8gVGVzdCBmb3Igc2FsdFxuXHQgICAgICAgICAgICBpZiAoY2lwaGVydGV4dFdvcmRzWzBdID09IDB4NTM2MTZjNzQgJiYgY2lwaGVydGV4dFdvcmRzWzFdID09IDB4NjU2NDVmNWYpIHtcblx0ICAgICAgICAgICAgICAgIC8vIEV4dHJhY3Qgc2FsdFxuXHQgICAgICAgICAgICAgICAgdmFyIHNhbHQgPSBXb3JkQXJyYXkuY3JlYXRlKGNpcGhlcnRleHRXb3Jkcy5zbGljZSgyLCA0KSk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFJlbW92ZSBzYWx0IGZyb20gY2lwaGVydGV4dFxuXHQgICAgICAgICAgICAgICAgY2lwaGVydGV4dFdvcmRzLnNwbGljZSgwLCA0KTtcblx0ICAgICAgICAgICAgICAgIGNpcGhlcnRleHQuc2lnQnl0ZXMgLT0gMTY7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gQ2lwaGVyUGFyYW1zLmNyZWF0ZSh7IGNpcGhlcnRleHQ6IGNpcGhlcnRleHQsIHNhbHQ6IHNhbHQgfSk7XG5cdCAgICAgICAgfVxuXHQgICAgfTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBIGNpcGhlciB3cmFwcGVyIHRoYXQgcmV0dXJucyBjaXBoZXJ0ZXh0IGFzIGEgc2VyaWFsaXphYmxlIGNpcGhlciBwYXJhbXMgb2JqZWN0LlxuXHQgICAgICovXG5cdCAgICB2YXIgU2VyaWFsaXphYmxlQ2lwaGVyID0gQ19saWIuU2VyaWFsaXphYmxlQ2lwaGVyID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmZpZ3VyYXRpb24gb3B0aW9ucy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7Rm9ybWF0dGVyfSBmb3JtYXQgVGhlIGZvcm1hdHRpbmcgc3RyYXRlZ3kgdG8gY29udmVydCBjaXBoZXIgcGFyYW0gb2JqZWN0cyB0byBhbmQgZnJvbSBhIHN0cmluZy4gRGVmYXVsdDogT3BlblNTTFxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNmZzogQmFzZS5leHRlbmQoe1xuXHQgICAgICAgICAgICBmb3JtYXQ6IE9wZW5TU0xGb3JtYXR0ZXJcblx0ICAgICAgICB9KSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEVuY3J5cHRzIGEgbWVzc2FnZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyfSBjaXBoZXIgVGhlIGNpcGhlciBhbGdvcml0aG0gdG8gdXNlLlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBlbmNyeXB0LlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSBrZXkgVGhlIGtleS5cblx0ICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gY2ZnIChPcHRpb25hbCkgVGhlIGNvbmZpZ3VyYXRpb24gb3B0aW9ucyB0byB1c2UgZm9yIHRoaXMgb3BlcmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7Q2lwaGVyUGFyYW1zfSBBIGNpcGhlciBwYXJhbXMgb2JqZWN0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2lwaGVydGV4dFBhcmFtcyA9IENyeXB0b0pTLmxpYi5TZXJpYWxpemFibGVDaXBoZXIuZW5jcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgbWVzc2FnZSwga2V5KTtcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlcnRleHRQYXJhbXMgPSBDcnlwdG9KUy5saWIuU2VyaWFsaXphYmxlQ2lwaGVyLmVuY3J5cHQoQ3J5cHRvSlMuYWxnby5BRVMsIG1lc3NhZ2UsIGtleSwgeyBpdjogaXYgfSk7XG5cdCAgICAgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0UGFyYW1zID0gQ3J5cHRvSlMubGliLlNlcmlhbGl6YWJsZUNpcGhlci5lbmNyeXB0KENyeXB0b0pTLmFsZ28uQUVTLCBtZXNzYWdlLCBrZXksIHsgaXY6IGl2LCBmb3JtYXQ6IENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMIH0pO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGVuY3J5cHQ6IGZ1bmN0aW9uIChjaXBoZXIsIG1lc3NhZ2UsIGtleSwgY2ZnKSB7XG5cdCAgICAgICAgICAgIC8vIEFwcGx5IGNvbmZpZyBkZWZhdWx0c1xuXHQgICAgICAgICAgICBjZmcgPSB0aGlzLmNmZy5leHRlbmQoY2ZnKTtcblxuXHQgICAgICAgICAgICAvLyBFbmNyeXB0XG5cdCAgICAgICAgICAgIHZhciBlbmNyeXB0b3IgPSBjaXBoZXIuY3JlYXRlRW5jcnlwdG9yKGtleSwgY2ZnKTtcblx0ICAgICAgICAgICAgdmFyIGNpcGhlcnRleHQgPSBlbmNyeXB0b3IuZmluYWxpemUobWVzc2FnZSk7XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGNpcGhlckNmZyA9IGVuY3J5cHRvci5jZmc7XG5cblx0ICAgICAgICAgICAgLy8gQ3JlYXRlIGFuZCByZXR1cm4gc2VyaWFsaXphYmxlIGNpcGhlciBwYXJhbXNcblx0ICAgICAgICAgICAgcmV0dXJuIENpcGhlclBhcmFtcy5jcmVhdGUoe1xuXHQgICAgICAgICAgICAgICAgY2lwaGVydGV4dDogY2lwaGVydGV4dCxcblx0ICAgICAgICAgICAgICAgIGtleToga2V5LFxuXHQgICAgICAgICAgICAgICAgaXY6IGNpcGhlckNmZy5pdixcblx0ICAgICAgICAgICAgICAgIGFsZ29yaXRobTogY2lwaGVyLFxuXHQgICAgICAgICAgICAgICAgbW9kZTogY2lwaGVyQ2ZnLm1vZGUsXG5cdCAgICAgICAgICAgICAgICBwYWRkaW5nOiBjaXBoZXJDZmcucGFkZGluZyxcblx0ICAgICAgICAgICAgICAgIGJsb2NrU2l6ZTogY2lwaGVyLmJsb2NrU2l6ZSxcblx0ICAgICAgICAgICAgICAgIGZvcm1hdHRlcjogY2ZnLmZvcm1hdFxuXHQgICAgICAgICAgICB9KTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogRGVjcnlwdHMgc2VyaWFsaXplZCBjaXBoZXJ0ZXh0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJ9IGNpcGhlciBUaGUgY2lwaGVyIGFsZ29yaXRobSB0byB1c2UuXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJQYXJhbXN8c3RyaW5nfSBjaXBoZXJ0ZXh0IFRoZSBjaXBoZXJ0ZXh0IHRvIGRlY3J5cHQuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IGtleSBUaGUga2V5LlxuXHQgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBwbGFpbnRleHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBwbGFpbnRleHQgPSBDcnlwdG9KUy5saWIuU2VyaWFsaXphYmxlQ2lwaGVyLmRlY3J5cHQoQ3J5cHRvSlMuYWxnby5BRVMsIGZvcm1hdHRlZENpcGhlcnRleHQsIGtleSwgeyBpdjogaXYsIGZvcm1hdDogQ3J5cHRvSlMuZm9ybWF0Lk9wZW5TU0wgfSk7XG5cdCAgICAgICAgICogICAgIHZhciBwbGFpbnRleHQgPSBDcnlwdG9KUy5saWIuU2VyaWFsaXphYmxlQ2lwaGVyLmRlY3J5cHQoQ3J5cHRvSlMuYWxnby5BRVMsIGNpcGhlcnRleHRQYXJhbXMsIGtleSwgeyBpdjogaXYsIGZvcm1hdDogQ3J5cHRvSlMuZm9ybWF0Lk9wZW5TU0wgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgZGVjcnlwdDogZnVuY3Rpb24gKGNpcGhlciwgY2lwaGVydGV4dCwga2V5LCBjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIGNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnQgc3RyaW5nIHRvIENpcGhlclBhcmFtc1xuXHQgICAgICAgICAgICBjaXBoZXJ0ZXh0ID0gdGhpcy5fcGFyc2UoY2lwaGVydGV4dCwgY2ZnLmZvcm1hdCk7XG5cblx0ICAgICAgICAgICAgLy8gRGVjcnlwdFxuXHQgICAgICAgICAgICB2YXIgcGxhaW50ZXh0ID0gY2lwaGVyLmNyZWF0ZURlY3J5cHRvcihrZXksIGNmZykuZmluYWxpemUoY2lwaGVydGV4dC5jaXBoZXJ0ZXh0KTtcblxuXHQgICAgICAgICAgICByZXR1cm4gcGxhaW50ZXh0O1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBzZXJpYWxpemVkIGNpcGhlcnRleHQgdG8gQ2lwaGVyUGFyYW1zLFxuXHQgICAgICAgICAqIGVsc2UgYXNzdW1lZCBDaXBoZXJQYXJhbXMgYWxyZWFkeSBhbmQgcmV0dXJucyBjaXBoZXJ0ZXh0IHVuY2hhbmdlZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyUGFyYW1zfHN0cmluZ30gY2lwaGVydGV4dCBUaGUgY2lwaGVydGV4dC5cblx0ICAgICAgICAgKiBAcGFyYW0ge0Zvcm1hdHRlcn0gZm9ybWF0IFRoZSBmb3JtYXR0aW5nIHN0cmF0ZWd5IHRvIHVzZSB0byBwYXJzZSBzZXJpYWxpemVkIGNpcGhlcnRleHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJQYXJhbXN9IFRoZSB1bnNlcmlhbGl6ZWQgY2lwaGVydGV4dC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlcnRleHRQYXJhbXMgPSBDcnlwdG9KUy5saWIuU2VyaWFsaXphYmxlQ2lwaGVyLl9wYXJzZShjaXBoZXJ0ZXh0U3RyaW5nT3JQYXJhbXMsIGZvcm1hdCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgX3BhcnNlOiBmdW5jdGlvbiAoY2lwaGVydGV4dCwgZm9ybWF0KSB7XG5cdCAgICAgICAgICAgIGlmICh0eXBlb2YgY2lwaGVydGV4dCA9PSAnc3RyaW5nJykge1xuXHQgICAgICAgICAgICAgICAgcmV0dXJuIGZvcm1hdC5wYXJzZShjaXBoZXJ0ZXh0LCB0aGlzKTtcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIHJldHVybiBjaXBoZXJ0ZXh0O1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogS2V5IGRlcml2YXRpb24gZnVuY3Rpb24gbmFtZXNwYWNlLlxuXHQgICAgICovXG5cdCAgICB2YXIgQ19rZGYgPSBDLmtkZiA9IHt9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIE9wZW5TU0wga2V5IGRlcml2YXRpb24gZnVuY3Rpb24uXG5cdCAgICAgKi9cblx0ICAgIHZhciBPcGVuU1NMS2RmID0gQ19rZGYuT3BlblNTTCA9IHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBEZXJpdmVzIGEga2V5IGFuZCBJViBmcm9tIGEgcGFzc3dvcmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gcGFzc3dvcmQgVGhlIHBhc3N3b3JkIHRvIGRlcml2ZSBmcm9tLlxuXHQgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBrZXlTaXplIFRoZSBzaXplIGluIHdvcmRzIG9mIHRoZSBrZXkgdG8gZ2VuZXJhdGUuXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IGl2U2l6ZSBUaGUgc2l6ZSBpbiB3b3JkcyBvZiB0aGUgSVYgdG8gZ2VuZXJhdGUuXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBzYWx0IChPcHRpb25hbCkgQSA2NC1iaXQgc2FsdCB0byB1c2UuIElmIG9taXR0ZWQsIGEgc2FsdCB3aWxsIGJlIGdlbmVyYXRlZCByYW5kb21seS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge0NpcGhlclBhcmFtc30gQSBjaXBoZXIgcGFyYW1zIG9iamVjdCB3aXRoIHRoZSBrZXksIElWLCBhbmQgc2FsdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGRlcml2ZWRQYXJhbXMgPSBDcnlwdG9KUy5rZGYuT3BlblNTTC5leGVjdXRlKCdQYXNzd29yZCcsIDI1Ni8zMiwgMTI4LzMyKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGRlcml2ZWRQYXJhbXMgPSBDcnlwdG9KUy5rZGYuT3BlblNTTC5leGVjdXRlKCdQYXNzd29yZCcsIDI1Ni8zMiwgMTI4LzMyLCAnc2FsdHNhbHQnKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBleGVjdXRlOiBmdW5jdGlvbiAocGFzc3dvcmQsIGtleVNpemUsIGl2U2l6ZSwgc2FsdCkge1xuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSByYW5kb20gc2FsdFxuXHQgICAgICAgICAgICBpZiAoIXNhbHQpIHtcblx0ICAgICAgICAgICAgICAgIHNhbHQgPSBXb3JkQXJyYXkucmFuZG9tKDY0LzgpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gRGVyaXZlIGtleSBhbmQgSVZcblx0ICAgICAgICAgICAgdmFyIGtleSA9IEV2cEtERi5jcmVhdGUoeyBrZXlTaXplOiBrZXlTaXplICsgaXZTaXplIH0pLmNvbXB1dGUocGFzc3dvcmQsIHNhbHQpO1xuXG5cdCAgICAgICAgICAgIC8vIFNlcGFyYXRlIGtleSBhbmQgSVZcblx0ICAgICAgICAgICAgdmFyIGl2ID0gV29yZEFycmF5LmNyZWF0ZShrZXkud29yZHMuc2xpY2Uoa2V5U2l6ZSksIGl2U2l6ZSAqIDQpO1xuXHQgICAgICAgICAgICBrZXkuc2lnQnl0ZXMgPSBrZXlTaXplICogNDtcblxuXHQgICAgICAgICAgICAvLyBSZXR1cm4gcGFyYW1zXG5cdCAgICAgICAgICAgIHJldHVybiBDaXBoZXJQYXJhbXMuY3JlYXRlKHsga2V5OiBrZXksIGl2OiBpdiwgc2FsdDogc2FsdCB9KTtcblx0ICAgICAgICB9XG5cdCAgICB9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEEgc2VyaWFsaXphYmxlIGNpcGhlciB3cmFwcGVyIHRoYXQgZGVyaXZlcyB0aGUga2V5IGZyb20gYSBwYXNzd29yZCxcblx0ICAgICAqIGFuZCByZXR1cm5zIGNpcGhlcnRleHQgYXMgYSBzZXJpYWxpemFibGUgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgKi9cblx0ICAgIHZhciBQYXNzd29yZEJhc2VkQ2lwaGVyID0gQ19saWIuUGFzc3dvcmRCYXNlZENpcGhlciA9IFNlcmlhbGl6YWJsZUNpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmZpZ3VyYXRpb24gb3B0aW9ucy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7S0RGfSBrZGYgVGhlIGtleSBkZXJpdmF0aW9uIGZ1bmN0aW9uIHRvIHVzZSB0byBnZW5lcmF0ZSBhIGtleSBhbmQgSVYgZnJvbSBhIHBhc3N3b3JkLiBEZWZhdWx0OiBPcGVuU1NMXG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2ZnOiBTZXJpYWxpemFibGVDaXBoZXIuY2ZnLmV4dGVuZCh7XG5cdCAgICAgICAgICAgIGtkZjogT3BlblNTTEtkZlxuXHQgICAgICAgIH0pLFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogRW5jcnlwdHMgYSBtZXNzYWdlIHVzaW5nIGEgcGFzc3dvcmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0NpcGhlcn0gY2lwaGVyIFRoZSBjaXBoZXIgYWxnb3JpdGhtIHRvIHVzZS5cblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gZW5jcnlwdC5cblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gcGFzc3dvcmQgVGhlIHBhc3N3b3JkLlxuXHQgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBvcGVyYXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJQYXJhbXN9IEEgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0UGFyYW1zID0gQ3J5cHRvSlMubGliLlBhc3N3b3JkQmFzZWRDaXBoZXIuZW5jcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgbWVzc2FnZSwgJ3Bhc3N3b3JkJyk7XG5cdCAgICAgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0UGFyYW1zID0gQ3J5cHRvSlMubGliLlBhc3N3b3JkQmFzZWRDaXBoZXIuZW5jcnlwdChDcnlwdG9KUy5hbGdvLkFFUywgbWVzc2FnZSwgJ3Bhc3N3b3JkJywgeyBmb3JtYXQ6IENyeXB0b0pTLmZvcm1hdC5PcGVuU1NMIH0pO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGVuY3J5cHQ6IGZ1bmN0aW9uIChjaXBoZXIsIG1lc3NhZ2UsIHBhc3N3b3JkLCBjZmcpIHtcblx0ICAgICAgICAgICAgLy8gQXBwbHkgY29uZmlnIGRlZmF1bHRzXG5cdCAgICAgICAgICAgIGNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXG5cdCAgICAgICAgICAgIC8vIERlcml2ZSBrZXkgYW5kIG90aGVyIHBhcmFtc1xuXHQgICAgICAgICAgICB2YXIgZGVyaXZlZFBhcmFtcyA9IGNmZy5rZGYuZXhlY3V0ZShwYXNzd29yZCwgY2lwaGVyLmtleVNpemUsIGNpcGhlci5pdlNpemUpO1xuXG5cdCAgICAgICAgICAgIC8vIEFkZCBJViB0byBjb25maWdcblx0ICAgICAgICAgICAgY2ZnLml2ID0gZGVyaXZlZFBhcmFtcy5pdjtcblxuXHQgICAgICAgICAgICAvLyBFbmNyeXB0XG5cdCAgICAgICAgICAgIHZhciBjaXBoZXJ0ZXh0ID0gU2VyaWFsaXphYmxlQ2lwaGVyLmVuY3J5cHQuY2FsbCh0aGlzLCBjaXBoZXIsIG1lc3NhZ2UsIGRlcml2ZWRQYXJhbXMua2V5LCBjZmcpO1xuXG5cdCAgICAgICAgICAgIC8vIE1peCBpbiBkZXJpdmVkIHBhcmFtc1xuXHQgICAgICAgICAgICBjaXBoZXJ0ZXh0Lm1peEluKGRlcml2ZWRQYXJhbXMpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBjaXBoZXJ0ZXh0O1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBEZWNyeXB0cyBzZXJpYWxpemVkIGNpcGhlcnRleHQgdXNpbmcgYSBwYXNzd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyfSBjaXBoZXIgVGhlIGNpcGhlciBhbGdvcml0aG0gdG8gdXNlLlxuXHQgICAgICAgICAqIEBwYXJhbSB7Q2lwaGVyUGFyYW1zfHN0cmluZ30gY2lwaGVydGV4dCBUaGUgY2lwaGVydGV4dCB0byBkZWNyeXB0LlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSBwYXNzd29yZCBUaGUgcGFzc3dvcmQuXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIG9wZXJhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHBsYWludGV4dC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHBsYWludGV4dCA9IENyeXB0b0pTLmxpYi5QYXNzd29yZEJhc2VkQ2lwaGVyLmRlY3J5cHQoQ3J5cHRvSlMuYWxnby5BRVMsIGZvcm1hdHRlZENpcGhlcnRleHQsICdwYXNzd29yZCcsIHsgZm9ybWF0OiBDcnlwdG9KUy5mb3JtYXQuT3BlblNTTCB9KTtcblx0ICAgICAgICAgKiAgICAgdmFyIHBsYWludGV4dCA9IENyeXB0b0pTLmxpYi5QYXNzd29yZEJhc2VkQ2lwaGVyLmRlY3J5cHQoQ3J5cHRvSlMuYWxnby5BRVMsIGNpcGhlcnRleHRQYXJhbXMsICdwYXNzd29yZCcsIHsgZm9ybWF0OiBDcnlwdG9KUy5mb3JtYXQuT3BlblNTTCB9KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBkZWNyeXB0OiBmdW5jdGlvbiAoY2lwaGVyLCBjaXBoZXJ0ZXh0LCBwYXNzd29yZCwgY2ZnKSB7XG5cdCAgICAgICAgICAgIC8vIEFwcGx5IGNvbmZpZyBkZWZhdWx0c1xuXHQgICAgICAgICAgICBjZmcgPSB0aGlzLmNmZy5leHRlbmQoY2ZnKTtcblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0IHN0cmluZyB0byBDaXBoZXJQYXJhbXNcblx0ICAgICAgICAgICAgY2lwaGVydGV4dCA9IHRoaXMuX3BhcnNlKGNpcGhlcnRleHQsIGNmZy5mb3JtYXQpO1xuXG5cdCAgICAgICAgICAgIC8vIERlcml2ZSBrZXkgYW5kIG90aGVyIHBhcmFtc1xuXHQgICAgICAgICAgICB2YXIgZGVyaXZlZFBhcmFtcyA9IGNmZy5rZGYuZXhlY3V0ZShwYXNzd29yZCwgY2lwaGVyLmtleVNpemUsIGNpcGhlci5pdlNpemUsIGNpcGhlcnRleHQuc2FsdCk7XG5cblx0ICAgICAgICAgICAgLy8gQWRkIElWIHRvIGNvbmZpZ1xuXHQgICAgICAgICAgICBjZmcuaXYgPSBkZXJpdmVkUGFyYW1zLml2O1xuXG5cdCAgICAgICAgICAgIC8vIERlY3J5cHRcblx0ICAgICAgICAgICAgdmFyIHBsYWludGV4dCA9IFNlcmlhbGl6YWJsZUNpcGhlci5kZWNyeXB0LmNhbGwodGhpcywgY2lwaGVyLCBjaXBoZXJ0ZXh0LCBkZXJpdmVkUGFyYW1zLmtleSwgY2ZnKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gcGxhaW50ZXh0O1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXHR9KCkpO1xuXG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5KSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeSgpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0cm9vdC5DcnlwdG9KUyA9IGZhY3RvcnkoKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoKSB7XG5cblx0LyoqXG5cdCAqIENyeXB0b0pTIGNvcmUgY29tcG9uZW50cy5cblx0ICovXG5cdHZhciBDcnlwdG9KUyA9IENyeXB0b0pTIHx8IChmdW5jdGlvbiAoTWF0aCwgdW5kZWZpbmVkKSB7XG5cdCAgICAvKlxuXHQgICAgICogTG9jYWwgcG9seWZpbCBvZiBPYmplY3QuY3JlYXRlXG5cdCAgICAgKi9cblx0ICAgIHZhciBjcmVhdGUgPSBPYmplY3QuY3JlYXRlIHx8IChmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgZnVuY3Rpb24gRigpIHt9O1xuXG5cdCAgICAgICAgcmV0dXJuIGZ1bmN0aW9uIChvYmopIHtcblx0ICAgICAgICAgICAgdmFyIHN1YnR5cGU7XG5cblx0ICAgICAgICAgICAgRi5wcm90b3R5cGUgPSBvYmo7XG5cblx0ICAgICAgICAgICAgc3VidHlwZSA9IG5ldyBGKCk7XG5cblx0ICAgICAgICAgICAgRi5wcm90b3R5cGUgPSBudWxsO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBzdWJ0eXBlO1xuXHQgICAgICAgIH07XG5cdCAgICB9KCkpXG5cblx0ICAgIC8qKlxuXHQgICAgICogQ3J5cHRvSlMgbmFtZXNwYWNlLlxuXHQgICAgICovXG5cdCAgICB2YXIgQyA9IHt9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIExpYnJhcnkgbmFtZXNwYWNlLlxuXHQgICAgICovXG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYiA9IHt9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEJhc2Ugb2JqZWN0IGZvciBwcm90b3R5cGFsIGluaGVyaXRhbmNlLlxuXHQgICAgICovXG5cdCAgICB2YXIgQmFzZSA9IENfbGliLkJhc2UgPSAoZnVuY3Rpb24gKCkge1xuXG5cblx0ICAgICAgICByZXR1cm4ge1xuXHQgICAgICAgICAgICAvKipcblx0ICAgICAgICAgICAgICogQ3JlYXRlcyBhIG5ldyBvYmplY3QgdGhhdCBpbmhlcml0cyBmcm9tIHRoaXMgb2JqZWN0LlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAcGFyYW0ge09iamVjdH0gb3ZlcnJpZGVzIFByb3BlcnRpZXMgdG8gY29weSBpbnRvIHRoZSBuZXcgb2JqZWN0LlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAcmV0dXJuIHtPYmplY3R9IFRoZSBuZXcgb2JqZWN0LlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqICAgICB2YXIgTXlUeXBlID0gQ3J5cHRvSlMubGliLkJhc2UuZXh0ZW5kKHtcblx0ICAgICAgICAgICAgICogICAgICAgICBmaWVsZDogJ3ZhbHVlJyxcblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogICAgICAgICBtZXRob2Q6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgICogICAgICAgICB9XG5cdCAgICAgICAgICAgICAqICAgICB9KTtcblx0ICAgICAgICAgICAgICovXG5cdCAgICAgICAgICAgIGV4dGVuZDogZnVuY3Rpb24gKG92ZXJyaWRlcykge1xuXHQgICAgICAgICAgICAgICAgLy8gU3Bhd25cblx0ICAgICAgICAgICAgICAgIHZhciBzdWJ0eXBlID0gY3JlYXRlKHRoaXMpO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBBdWdtZW50XG5cdCAgICAgICAgICAgICAgICBpZiAob3ZlcnJpZGVzKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgc3VidHlwZS5taXhJbihvdmVycmlkZXMpO1xuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAvLyBDcmVhdGUgZGVmYXVsdCBpbml0aWFsaXplclxuXHQgICAgICAgICAgICAgICAgaWYgKCFzdWJ0eXBlLmhhc093blByb3BlcnR5KCdpbml0JykgfHwgdGhpcy5pbml0ID09PSBzdWJ0eXBlLmluaXQpIHtcblx0ICAgICAgICAgICAgICAgICAgICBzdWJ0eXBlLmluaXQgPSBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHN1YnR5cGUuJHN1cGVyLmluaXQuYXBwbHkodGhpcywgYXJndW1lbnRzKTtcblx0ICAgICAgICAgICAgICAgICAgICB9O1xuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAvLyBJbml0aWFsaXplcidzIHByb3RvdHlwZSBpcyB0aGUgc3VidHlwZSBvYmplY3Rcblx0ICAgICAgICAgICAgICAgIHN1YnR5cGUuaW5pdC5wcm90b3R5cGUgPSBzdWJ0eXBlO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBSZWZlcmVuY2Ugc3VwZXJ0eXBlXG5cdCAgICAgICAgICAgICAgICBzdWJ0eXBlLiRzdXBlciA9IHRoaXM7XG5cblx0ICAgICAgICAgICAgICAgIHJldHVybiBzdWJ0eXBlO1xuXHQgICAgICAgICAgICB9LFxuXG5cdCAgICAgICAgICAgIC8qKlxuXHQgICAgICAgICAgICAgKiBFeHRlbmRzIHRoaXMgb2JqZWN0IGFuZCBydW5zIHRoZSBpbml0IG1ldGhvZC5cblx0ICAgICAgICAgICAgICogQXJndW1lbnRzIHRvIGNyZWF0ZSgpIHdpbGwgYmUgcGFzc2VkIHRvIGluaXQoKS5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQHJldHVybiB7T2JqZWN0fSBUaGUgbmV3IG9iamVjdC5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgdmFyIGluc3RhbmNlID0gTXlUeXBlLmNyZWF0ZSgpO1xuXHQgICAgICAgICAgICAgKi9cblx0ICAgICAgICAgICAgY3JlYXRlOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgaW5zdGFuY2UgPSB0aGlzLmV4dGVuZCgpO1xuXHQgICAgICAgICAgICAgICAgaW5zdGFuY2UuaW5pdC5hcHBseShpbnN0YW5jZSwgYXJndW1lbnRzKTtcblxuXHQgICAgICAgICAgICAgICAgcmV0dXJuIGluc3RhbmNlO1xuXHQgICAgICAgICAgICB9LFxuXG5cdCAgICAgICAgICAgIC8qKlxuXHQgICAgICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQgb2JqZWN0LlxuXHQgICAgICAgICAgICAgKiBPdmVycmlkZSB0aGlzIG1ldGhvZCB0byBhZGQgc29tZSBsb2dpYyB3aGVuIHlvdXIgb2JqZWN0cyBhcmUgY3JlYXRlZC5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogICAgIHZhciBNeVR5cGUgPSBDcnlwdG9KUy5saWIuQmFzZS5leHRlbmQoe1xuXHQgICAgICAgICAgICAgKiAgICAgICAgIGluaXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgICogICAgICAgICAgICAgLy8gLi4uXG5cdCAgICAgICAgICAgICAqICAgICAgICAgfVxuXHQgICAgICAgICAgICAgKiAgICAgfSk7XG5cdCAgICAgICAgICAgICAqL1xuXHQgICAgICAgICAgICBpbml0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIH0sXG5cblx0ICAgICAgICAgICAgLyoqXG5cdCAgICAgICAgICAgICAqIENvcGllcyBwcm9wZXJ0aWVzIGludG8gdGhpcyBvYmplY3QuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEBwYXJhbSB7T2JqZWN0fSBwcm9wZXJ0aWVzIFRoZSBwcm9wZXJ0aWVzIHRvIG1peCBpbi5cblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgICAgICpcblx0ICAgICAgICAgICAgICogICAgIE15VHlwZS5taXhJbih7XG5cdCAgICAgICAgICAgICAqICAgICAgICAgZmllbGQ6ICd2YWx1ZSdcblx0ICAgICAgICAgICAgICogICAgIH0pO1xuXHQgICAgICAgICAgICAgKi9cblx0ICAgICAgICAgICAgbWl4SW46IGZ1bmN0aW9uIChwcm9wZXJ0aWVzKSB7XG5cdCAgICAgICAgICAgICAgICBmb3IgKHZhciBwcm9wZXJ0eU5hbWUgaW4gcHJvcGVydGllcykge1xuXHQgICAgICAgICAgICAgICAgICAgIGlmIChwcm9wZXJ0aWVzLmhhc093blByb3BlcnR5KHByb3BlcnR5TmFtZSkpIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdGhpc1twcm9wZXJ0eU5hbWVdID0gcHJvcGVydGllc1twcm9wZXJ0eU5hbWVdO1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgLy8gSUUgd29uJ3QgY29weSB0b1N0cmluZyB1c2luZyB0aGUgbG9vcCBhYm92ZVxuXHQgICAgICAgICAgICAgICAgaWYgKHByb3BlcnRpZXMuaGFzT3duUHJvcGVydHkoJ3RvU3RyaW5nJykpIHtcblx0ICAgICAgICAgICAgICAgICAgICB0aGlzLnRvU3RyaW5nID0gcHJvcGVydGllcy50b1N0cmluZztcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfSxcblxuXHQgICAgICAgICAgICAvKipcblx0ICAgICAgICAgICAgICogQ3JlYXRlcyBhIGNvcHkgb2YgdGhpcyBvYmplY3QuXG5cdCAgICAgICAgICAgICAqXG5cdCAgICAgICAgICAgICAqIEByZXR1cm4ge09iamVjdH0gVGhlIGNsb25lLlxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAgICAgKlxuXHQgICAgICAgICAgICAgKiAgICAgdmFyIGNsb25lID0gaW5zdGFuY2UuY2xvbmUoKTtcblx0ICAgICAgICAgICAgICovXG5cdCAgICAgICAgICAgIGNsb25lOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgICAgICByZXR1cm4gdGhpcy5pbml0LnByb3RvdHlwZS5leHRlbmQodGhpcyk7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9O1xuXHQgICAgfSgpKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBbiBhcnJheSBvZiAzMi1iaXQgd29yZHMuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtBcnJheX0gd29yZHMgVGhlIGFycmF5IG9mIDMyLWJpdCB3b3Jkcy5cblx0ICAgICAqIEBwcm9wZXJ0eSB7bnVtYmVyfSBzaWdCeXRlcyBUaGUgbnVtYmVyIG9mIHNpZ25pZmljYW50IGJ5dGVzIGluIHRoaXMgd29yZCBhcnJheS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFdvcmRBcnJheSA9IENfbGliLldvcmRBcnJheSA9IEJhc2UuZXh0ZW5kKHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7QXJyYXl9IHdvcmRzIChPcHRpb25hbCkgQW4gYXJyYXkgb2YgMzItYml0IHdvcmRzLlxuXHQgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBzaWdCeXRlcyAoT3B0aW9uYWwpIFRoZSBudW1iZXIgb2Ygc2lnbmlmaWNhbnQgYnl0ZXMgaW4gdGhlIHdvcmRzLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMubGliLldvcmRBcnJheS5jcmVhdGUoKTtcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLmxpYi5Xb3JkQXJyYXkuY3JlYXRlKFsweDAwMDEwMjAzLCAweDA0MDUwNjA3XSk7XG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5saWIuV29yZEFycmF5LmNyZWF0ZShbMHgwMDAxMDIwMywgMHgwNDA1MDYwN10sIDYpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGluaXQ6IGZ1bmN0aW9uICh3b3Jkcywgc2lnQnl0ZXMpIHtcblx0ICAgICAgICAgICAgd29yZHMgPSB0aGlzLndvcmRzID0gd29yZHMgfHwgW107XG5cblx0ICAgICAgICAgICAgaWYgKHNpZ0J5dGVzICE9IHVuZGVmaW5lZCkge1xuXHQgICAgICAgICAgICAgICAgdGhpcy5zaWdCeXRlcyA9IHNpZ0J5dGVzO1xuXHQgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgdGhpcy5zaWdCeXRlcyA9IHdvcmRzLmxlbmd0aCAqIDQ7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgdGhpcyB3b3JkIGFycmF5IHRvIGEgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtFbmNvZGVyfSBlbmNvZGVyIChPcHRpb25hbCkgVGhlIGVuY29kaW5nIHN0cmF0ZWd5IHRvIHVzZS4gRGVmYXVsdDogQ3J5cHRvSlMuZW5jLkhleFxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7c3RyaW5nfSBUaGUgc3RyaW5naWZpZWQgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHN0cmluZyA9IHdvcmRBcnJheSArICcnO1xuXHQgICAgICAgICAqICAgICB2YXIgc3RyaW5nID0gd29yZEFycmF5LnRvU3RyaW5nKCk7XG5cdCAgICAgICAgICogICAgIHZhciBzdHJpbmcgPSB3b3JkQXJyYXkudG9TdHJpbmcoQ3J5cHRvSlMuZW5jLlV0ZjgpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHRvU3RyaW5nOiBmdW5jdGlvbiAoZW5jb2Rlcikge1xuXHQgICAgICAgICAgICByZXR1cm4gKGVuY29kZXIgfHwgSGV4KS5zdHJpbmdpZnkodGhpcyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmNhdGVuYXRlcyBhIHdvcmQgYXJyYXkgdG8gdGhpcyB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBUaGUgd29yZCBhcnJheSB0byBhcHBlbmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoaXMgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgd29yZEFycmF5MS5jb25jYXQod29yZEFycmF5Mik7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY29uY2F0OiBmdW5jdGlvbiAod29yZEFycmF5KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgdGhpc1dvcmRzID0gdGhpcy53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHRoYXRXb3JkcyA9IHdvcmRBcnJheS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHRoaXNTaWdCeXRlcyA9IHRoaXMuc2lnQnl0ZXM7XG5cdCAgICAgICAgICAgIHZhciB0aGF0U2lnQnl0ZXMgPSB3b3JkQXJyYXkuc2lnQnl0ZXM7XG5cblx0ICAgICAgICAgICAgLy8gQ2xhbXAgZXhjZXNzIGJpdHNcblx0ICAgICAgICAgICAgdGhpcy5jbGFtcCgpO1xuXG5cdCAgICAgICAgICAgIC8vIENvbmNhdFxuXHQgICAgICAgICAgICBpZiAodGhpc1NpZ0J5dGVzICUgNCkge1xuXHQgICAgICAgICAgICAgICAgLy8gQ29weSBvbmUgYnl0ZSBhdCBhIHRpbWVcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhhdFNpZ0J5dGVzOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgdGhhdEJ5dGUgPSAodGhhdFdvcmRzW2kgPj4+IDJdID4+PiAoMjQgLSAoaSAlIDQpICogOCkpICYgMHhmZjtcblx0ICAgICAgICAgICAgICAgICAgICB0aGlzV29yZHNbKHRoaXNTaWdCeXRlcyArIGkpID4+PiAyXSB8PSB0aGF0Qnl0ZSA8PCAoMjQgLSAoKHRoaXNTaWdCeXRlcyArIGkpICUgNCkgKiA4KTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIC8vIENvcHkgb25lIHdvcmQgYXQgYSB0aW1lXG5cdCAgICAgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRoYXRTaWdCeXRlczsgaSArPSA0KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdGhpc1dvcmRzWyh0aGlzU2lnQnl0ZXMgKyBpKSA+Pj4gMl0gPSB0aGF0V29yZHNbaSA+Pj4gMl07XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgdGhpcy5zaWdCeXRlcyArPSB0aGF0U2lnQnl0ZXM7XG5cblx0ICAgICAgICAgICAgLy8gQ2hhaW5hYmxlXG5cdCAgICAgICAgICAgIHJldHVybiB0aGlzO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBSZW1vdmVzIGluc2lnbmlmaWNhbnQgYml0cy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgd29yZEFycmF5LmNsYW1wKCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2xhbXA6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IHRoaXMud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBzaWdCeXRlcyA9IHRoaXMuc2lnQnl0ZXM7XG5cblx0ICAgICAgICAgICAgLy8gQ2xhbXBcblx0ICAgICAgICAgICAgd29yZHNbc2lnQnl0ZXMgPj4+IDJdICY9IDB4ZmZmZmZmZmYgPDwgKDMyIC0gKHNpZ0J5dGVzICUgNCkgKiA4KTtcblx0ICAgICAgICAgICAgd29yZHMubGVuZ3RoID0gTWF0aC5jZWlsKHNpZ0J5dGVzIC8gNCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgYSBjb3B5IG9mIHRoaXMgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGNsb25lLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2xvbmUgPSB3b3JkQXJyYXkuY2xvbmUoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBCYXNlLmNsb25lLmNhbGwodGhpcyk7XG5cdCAgICAgICAgICAgIGNsb25lLndvcmRzID0gdGhpcy53b3Jkcy5zbGljZSgwKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gY2xvbmU7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgYSB3b3JkIGFycmF5IGZpbGxlZCB3aXRoIHJhbmRvbSBieXRlcy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBuQnl0ZXMgVGhlIG51bWJlciBvZiByYW5kb20gYnl0ZXMgdG8gZ2VuZXJhdGUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSByYW5kb20gd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLmxpYi5Xb3JkQXJyYXkucmFuZG9tKDE2KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICByYW5kb206IGZ1bmN0aW9uIChuQnl0ZXMpIHtcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gW107XG5cblx0ICAgICAgICAgICAgdmFyIHIgPSAoZnVuY3Rpb24gKG1fdykge1xuXHQgICAgICAgICAgICAgICAgdmFyIG1fdyA9IG1fdztcblx0ICAgICAgICAgICAgICAgIHZhciBtX3ogPSAweDNhZGU2OGIxO1xuXHQgICAgICAgICAgICAgICAgdmFyIG1hc2sgPSAweGZmZmZmZmZmO1xuXG5cdCAgICAgICAgICAgICAgICByZXR1cm4gZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAgICAgICAgIG1feiA9ICgweDkwNjkgKiAobV96ICYgMHhGRkZGKSArIChtX3ogPj4gMHgxMCkpICYgbWFzaztcblx0ICAgICAgICAgICAgICAgICAgICBtX3cgPSAoMHg0NjUwICogKG1fdyAmIDB4RkZGRikgKyAobV93ID4+IDB4MTApKSAmIG1hc2s7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIHJlc3VsdCA9ICgobV96IDw8IDB4MTApICsgbV93KSAmIG1hc2s7XG5cdCAgICAgICAgICAgICAgICAgICAgcmVzdWx0IC89IDB4MTAwMDAwMDAwO1xuXHQgICAgICAgICAgICAgICAgICAgIHJlc3VsdCArPSAwLjU7XG5cdCAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHJlc3VsdCAqIChNYXRoLnJhbmRvbSgpID4gLjUgPyAxIDogLTEpO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9KTtcblxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMCwgcmNhY2hlOyBpIDwgbkJ5dGVzOyBpICs9IDQpIHtcblx0ICAgICAgICAgICAgICAgIHZhciBfciA9IHIoKHJjYWNoZSB8fCBNYXRoLnJhbmRvbSgpKSAqIDB4MTAwMDAwMDAwKTtcblxuXHQgICAgICAgICAgICAgICAgcmNhY2hlID0gX3IoKSAqIDB4M2FkZTY3Yjc7XG5cdCAgICAgICAgICAgICAgICB3b3Jkcy5wdXNoKChfcigpICogMHgxMDAwMDAwMDApIHwgMCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gbmV3IFdvcmRBcnJheS5pbml0KHdvcmRzLCBuQnl0ZXMpO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEVuY29kZXIgbmFtZXNwYWNlLlxuXHQgICAgICovXG5cdCAgICB2YXIgQ19lbmMgPSBDLmVuYyA9IHt9O1xuXG5cdCAgICAvKipcblx0ICAgICAqIEhleCBlbmNvZGluZyBzdHJhdGVneS5cblx0ICAgICAqL1xuXHQgICAgdmFyIEhleCA9IENfZW5jLkhleCA9IHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBhIHdvcmQgYXJyYXkgdG8gYSBoZXggc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl9IHdvcmRBcnJheSBUaGUgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge3N0cmluZ30gVGhlIGhleCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBoZXhTdHJpbmcgPSBDcnlwdG9KUy5lbmMuSGV4LnN0cmluZ2lmeSh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHN0cmluZ2lmeTogZnVuY3Rpb24gKHdvcmRBcnJheSkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gd29yZEFycmF5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgc2lnQnl0ZXMgPSB3b3JkQXJyYXkuc2lnQnl0ZXM7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydFxuXHQgICAgICAgICAgICB2YXIgaGV4Q2hhcnMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzaWdCeXRlczsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgYml0ZSA9ICh3b3Jkc1tpID4+PiAyXSA+Pj4gKDI0IC0gKGkgJSA0KSAqIDgpKSAmIDB4ZmY7XG5cdCAgICAgICAgICAgICAgICBoZXhDaGFycy5wdXNoKChiaXRlID4+PiA0KS50b1N0cmluZygxNikpO1xuXHQgICAgICAgICAgICAgICAgaGV4Q2hhcnMucHVzaCgoYml0ZSAmIDB4MGYpLnRvU3RyaW5nKDE2KSk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gaGV4Q2hhcnMuam9pbignJyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgaGV4IHN0cmluZyB0byBhIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gaGV4U3RyIFRoZSBoZXggc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLmVuYy5IZXgucGFyc2UoaGV4U3RyaW5nKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBwYXJzZTogZnVuY3Rpb24gKGhleFN0cikge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgaGV4U3RyTGVuZ3RoID0gaGV4U3RyLmxlbmd0aDtcblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0XG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGhleFN0ckxlbmd0aDsgaSArPSAyKSB7XG5cdCAgICAgICAgICAgICAgICB3b3Jkc1tpID4+PiAzXSB8PSBwYXJzZUludChoZXhTdHIuc3Vic3RyKGksIDIpLCAxNikgPDwgKDI0IC0gKGkgJSA4KSAqIDQpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIG5ldyBXb3JkQXJyYXkuaW5pdCh3b3JkcywgaGV4U3RyTGVuZ3RoIC8gMik7XG5cdCAgICAgICAgfVxuXHQgICAgfTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBMYXRpbjEgZW5jb2Rpbmcgc3RyYXRlZ3kuXG5cdCAgICAgKi9cblx0ICAgIHZhciBMYXRpbjEgPSBDX2VuYy5MYXRpbjEgPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSB3b3JkIGFycmF5IHRvIGEgTGF0aW4xIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSB3b3JkQXJyYXkgVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBMYXRpbjEgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgbGF0aW4xU3RyaW5nID0gQ3J5cHRvSlMuZW5jLkxhdGluMS5zdHJpbmdpZnkod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBzdHJpbmdpZnk6IGZ1bmN0aW9uICh3b3JkQXJyYXkpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IHdvcmRBcnJheS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHNpZ0J5dGVzID0gd29yZEFycmF5LnNpZ0J5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIGxhdGluMUNoYXJzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2lnQnl0ZXM7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgdmFyIGJpdGUgPSAod29yZHNbaSA+Pj4gMl0gPj4+ICgyNCAtIChpICUgNCkgKiA4KSkgJiAweGZmO1xuXHQgICAgICAgICAgICAgICAgbGF0aW4xQ2hhcnMucHVzaChTdHJpbmcuZnJvbUNoYXJDb2RlKGJpdGUpKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBsYXRpbjFDaGFycy5qb2luKCcnKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSBMYXRpbjEgc3RyaW5nIHRvIGEgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSBsYXRpbjFTdHIgVGhlIExhdGluMSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMuZW5jLkxhdGluMS5wYXJzZShsYXRpbjFTdHJpbmcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHBhcnNlOiBmdW5jdGlvbiAobGF0aW4xU3RyKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBsYXRpbjFTdHJMZW5ndGggPSBsYXRpbjFTdHIubGVuZ3RoO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbGF0aW4xU3RyTGVuZ3RoOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHdvcmRzW2kgPj4+IDJdIHw9IChsYXRpbjFTdHIuY2hhckNvZGVBdChpKSAmIDB4ZmYpIDw8ICgyNCAtIChpICUgNCkgKiA4KTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBuZXcgV29yZEFycmF5LmluaXQod29yZHMsIGxhdGluMVN0ckxlbmd0aCk7XG5cdCAgICAgICAgfVxuXHQgICAgfTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBVVEYtOCBlbmNvZGluZyBzdHJhdGVneS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFV0ZjggPSBDX2VuYy5VdGY4ID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgd29yZCBhcnJheSB0byBhIFVURi04IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSB3b3JkQXJyYXkgVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBVVEYtOCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB1dGY4U3RyaW5nID0gQ3J5cHRvSlMuZW5jLlV0Zjguc3RyaW5naWZ5KHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgc3RyaW5naWZ5OiBmdW5jdGlvbiAod29yZEFycmF5KSB7XG5cdCAgICAgICAgICAgIHRyeSB7XG5cdCAgICAgICAgICAgICAgICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KGVzY2FwZShMYXRpbjEuc3RyaW5naWZ5KHdvcmRBcnJheSkpKTtcblx0ICAgICAgICAgICAgfSBjYXRjaCAoZSkge1xuXHQgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKCdNYWxmb3JtZWQgVVRGLTggZGF0YScpO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgVVRGLTggc3RyaW5nIHRvIGEgd29yZCBhcnJheS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7c3RyaW5nfSB1dGY4U3RyIFRoZSBVVEYtOCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMuZW5jLlV0ZjgucGFyc2UodXRmOFN0cmluZyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcGFyc2U6IGZ1bmN0aW9uICh1dGY4U3RyKSB7XG5cdCAgICAgICAgICAgIHJldHVybiBMYXRpbjEucGFyc2UodW5lc2NhcGUoZW5jb2RlVVJJQ29tcG9uZW50KHV0ZjhTdHIpKSk7XG5cdCAgICAgICAgfVxuXHQgICAgfTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBYnN0cmFjdCBidWZmZXJlZCBibG9jayBhbGdvcml0aG0gdGVtcGxhdGUuXG5cdCAgICAgKlxuXHQgICAgICogVGhlIHByb3BlcnR5IGJsb2NrU2l6ZSBtdXN0IGJlIGltcGxlbWVudGVkIGluIGEgY29uY3JldGUgc3VidHlwZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcHJvcGVydHkge251bWJlcn0gX21pbkJ1ZmZlclNpemUgVGhlIG51bWJlciBvZiBibG9ja3MgdGhhdCBzaG91bGQgYmUga2VwdCB1bnByb2Nlc3NlZCBpbiB0aGUgYnVmZmVyLiBEZWZhdWx0OiAwXG5cdCAgICAgKi9cblx0ICAgIHZhciBCdWZmZXJlZEJsb2NrQWxnb3JpdGhtID0gQ19saWIuQnVmZmVyZWRCbG9ja0FsZ29yaXRobSA9IEJhc2UuZXh0ZW5kKHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBSZXNldHMgdGhpcyBibG9jayBhbGdvcml0aG0ncyBkYXRhIGJ1ZmZlciB0byBpdHMgaW5pdGlhbCBzdGF0ZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgYnVmZmVyZWRCbG9ja0FsZ29yaXRobS5yZXNldCgpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHJlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIEluaXRpYWwgdmFsdWVzXG5cdCAgICAgICAgICAgIHRoaXMuX2RhdGEgPSBuZXcgV29yZEFycmF5LmluaXQoKTtcblx0ICAgICAgICAgICAgdGhpcy5fbkRhdGFCeXRlcyA9IDA7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEFkZHMgbmV3IGRhdGEgdG8gdGhpcyBibG9jayBhbGdvcml0aG0ncyBidWZmZXIuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IGRhdGEgVGhlIGRhdGEgdG8gYXBwZW5kLiBTdHJpbmdzIGFyZSBjb252ZXJ0ZWQgdG8gYSBXb3JkQXJyYXkgdXNpbmcgVVRGLTguXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIGJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0uX2FwcGVuZCgnZGF0YScpO1xuXHQgICAgICAgICAqICAgICBidWZmZXJlZEJsb2NrQWxnb3JpdGhtLl9hcHBlbmQod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBfYXBwZW5kOiBmdW5jdGlvbiAoZGF0YSkge1xuXHQgICAgICAgICAgICAvLyBDb252ZXJ0IHN0cmluZyB0byBXb3JkQXJyYXksIGVsc2UgYXNzdW1lIFdvcmRBcnJheSBhbHJlYWR5XG5cdCAgICAgICAgICAgIGlmICh0eXBlb2YgZGF0YSA9PSAnc3RyaW5nJykge1xuXHQgICAgICAgICAgICAgICAgZGF0YSA9IFV0ZjgucGFyc2UoZGF0YSk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBBcHBlbmRcblx0ICAgICAgICAgICAgdGhpcy5fZGF0YS5jb25jYXQoZGF0YSk7XG5cdCAgICAgICAgICAgIHRoaXMuX25EYXRhQnl0ZXMgKz0gZGF0YS5zaWdCeXRlcztcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogUHJvY2Vzc2VzIGF2YWlsYWJsZSBkYXRhIGJsb2Nrcy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIFRoaXMgbWV0aG9kIGludm9rZXMgX2RvUHJvY2Vzc0Jsb2NrKG9mZnNldCksIHdoaWNoIG11c3QgYmUgaW1wbGVtZW50ZWQgYnkgYSBjb25jcmV0ZSBzdWJ0eXBlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtib29sZWFufSBkb0ZsdXNoIFdoZXRoZXIgYWxsIGJsb2NrcyBhbmQgcGFydGlhbCBibG9ja3Mgc2hvdWxkIGJlIHByb2Nlc3NlZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHByb2Nlc3NlZCBkYXRhLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgcHJvY2Vzc2VkRGF0YSA9IGJ1ZmZlcmVkQmxvY2tBbGdvcml0aG0uX3Byb2Nlc3MoKTtcblx0ICAgICAgICAgKiAgICAgdmFyIHByb2Nlc3NlZERhdGEgPSBidWZmZXJlZEJsb2NrQWxnb3JpdGhtLl9wcm9jZXNzKCEhJ2ZsdXNoJyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgX3Byb2Nlc3M6IGZ1bmN0aW9uIChkb0ZsdXNoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgZGF0YSA9IHRoaXMuX2RhdGE7XG5cdCAgICAgICAgICAgIHZhciBkYXRhV29yZHMgPSBkYXRhLndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgZGF0YVNpZ0J5dGVzID0gZGF0YS5zaWdCeXRlcztcblx0ICAgICAgICAgICAgdmFyIGJsb2NrU2l6ZSA9IHRoaXMuYmxvY2tTaXplO1xuXHQgICAgICAgICAgICB2YXIgYmxvY2tTaXplQnl0ZXMgPSBibG9ja1NpemUgKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIENvdW50IGJsb2NrcyByZWFkeVxuXHQgICAgICAgICAgICB2YXIgbkJsb2Nrc1JlYWR5ID0gZGF0YVNpZ0J5dGVzIC8gYmxvY2tTaXplQnl0ZXM7XG5cdCAgICAgICAgICAgIGlmIChkb0ZsdXNoKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBSb3VuZCB1cCB0byBpbmNsdWRlIHBhcnRpYWwgYmxvY2tzXG5cdCAgICAgICAgICAgICAgICBuQmxvY2tzUmVhZHkgPSBNYXRoLmNlaWwobkJsb2Nrc1JlYWR5KTtcblx0ICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgIC8vIFJvdW5kIGRvd24gdG8gaW5jbHVkZSBvbmx5IGZ1bGwgYmxvY2tzLFxuXHQgICAgICAgICAgICAgICAgLy8gbGVzcyB0aGUgbnVtYmVyIG9mIGJsb2NrcyB0aGF0IG11c3QgcmVtYWluIGluIHRoZSBidWZmZXJcblx0ICAgICAgICAgICAgICAgIG5CbG9ja3NSZWFkeSA9IE1hdGgubWF4KChuQmxvY2tzUmVhZHkgfCAwKSAtIHRoaXMuX21pbkJ1ZmZlclNpemUsIDApO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gQ291bnQgd29yZHMgcmVhZHlcblx0ICAgICAgICAgICAgdmFyIG5Xb3Jkc1JlYWR5ID0gbkJsb2Nrc1JlYWR5ICogYmxvY2tTaXplO1xuXG5cdCAgICAgICAgICAgIC8vIENvdW50IGJ5dGVzIHJlYWR5XG5cdCAgICAgICAgICAgIHZhciBuQnl0ZXNSZWFkeSA9IE1hdGgubWluKG5Xb3Jkc1JlYWR5ICogNCwgZGF0YVNpZ0J5dGVzKTtcblxuXHQgICAgICAgICAgICAvLyBQcm9jZXNzIGJsb2Nrc1xuXHQgICAgICAgICAgICBpZiAobldvcmRzUmVhZHkpIHtcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIG9mZnNldCA9IDA7IG9mZnNldCA8IG5Xb3Jkc1JlYWR5OyBvZmZzZXQgKz0gYmxvY2tTaXplKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgLy8gUGVyZm9ybSBjb25jcmV0ZS1hbGdvcml0aG0gbG9naWNcblx0ICAgICAgICAgICAgICAgICAgICB0aGlzLl9kb1Byb2Nlc3NCbG9jayhkYXRhV29yZHMsIG9mZnNldCk7XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIC8vIFJlbW92ZSBwcm9jZXNzZWQgd29yZHNcblx0ICAgICAgICAgICAgICAgIHZhciBwcm9jZXNzZWRXb3JkcyA9IGRhdGFXb3Jkcy5zcGxpY2UoMCwgbldvcmRzUmVhZHkpO1xuXHQgICAgICAgICAgICAgICAgZGF0YS5zaWdCeXRlcyAtPSBuQnl0ZXNSZWFkeTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFJldHVybiBwcm9jZXNzZWQgd29yZHNcblx0ICAgICAgICAgICAgcmV0dXJuIG5ldyBXb3JkQXJyYXkuaW5pdChwcm9jZXNzZWRXb3JkcywgbkJ5dGVzUmVhZHkpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDcmVhdGVzIGEgY29weSBvZiB0aGlzIG9iamVjdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge09iamVjdH0gVGhlIGNsb25lLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgY2xvbmUgPSBidWZmZXJlZEJsb2NrQWxnb3JpdGhtLmNsb25lKCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2xvbmU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdmFyIGNsb25lID0gQmFzZS5jbG9uZS5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICBjbG9uZS5fZGF0YSA9IHRoaXMuX2RhdGEuY2xvbmUoKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gY2xvbmU7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9taW5CdWZmZXJTaXplOiAwXG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBYnN0cmFjdCBoYXNoZXIgdGVtcGxhdGUuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IGJsb2NrU2l6ZSBUaGUgbnVtYmVyIG9mIDMyLWJpdCB3b3JkcyB0aGlzIGhhc2hlciBvcGVyYXRlcyBvbi4gRGVmYXVsdDogMTYgKDUxMiBiaXRzKVxuXHQgICAgICovXG5cdCAgICB2YXIgSGFzaGVyID0gQ19saWIuSGFzaGVyID0gQnVmZmVyZWRCbG9ja0FsZ29yaXRobS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbmZpZ3VyYXRpb24gb3B0aW9ucy5cblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjZmc6IEJhc2UuZXh0ZW5kKCksXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBJbml0aWFsaXplcyBhIG5ld2x5IGNyZWF0ZWQgaGFzaGVyLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGlzIGhhc2ggY29tcHV0YXRpb24uXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBoYXNoZXIgPSBDcnlwdG9KUy5hbGdvLlNIQTI1Ni5jcmVhdGUoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBpbml0OiBmdW5jdGlvbiAoY2ZnKSB7XG5cdCAgICAgICAgICAgIC8vIEFwcGx5IGNvbmZpZyBkZWZhdWx0c1xuXHQgICAgICAgICAgICB0aGlzLmNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXG5cdCAgICAgICAgICAgIC8vIFNldCBpbml0aWFsIHZhbHVlc1xuXHQgICAgICAgICAgICB0aGlzLnJlc2V0KCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFJlc2V0cyB0aGlzIGhhc2hlciB0byBpdHMgaW5pdGlhbCBzdGF0ZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgaGFzaGVyLnJlc2V0KCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gUmVzZXQgZGF0YSBidWZmZXJcblx0ICAgICAgICAgICAgQnVmZmVyZWRCbG9ja0FsZ29yaXRobS5yZXNldC5jYWxsKHRoaXMpO1xuXG5cdCAgICAgICAgICAgIC8vIFBlcmZvcm0gY29uY3JldGUtaGFzaGVyIGxvZ2ljXG5cdCAgICAgICAgICAgIHRoaXMuX2RvUmVzZXQoKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogVXBkYXRlcyB0aGlzIGhhc2hlciB3aXRoIGEgbWVzc2FnZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZVVwZGF0ZSBUaGUgbWVzc2FnZSB0byBhcHBlbmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtIYXNoZXJ9IFRoaXMgaGFzaGVyLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBoYXNoZXIudXBkYXRlKCdtZXNzYWdlJyk7XG5cdCAgICAgICAgICogICAgIGhhc2hlci51cGRhdGUod29yZEFycmF5KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICB1cGRhdGU6IGZ1bmN0aW9uIChtZXNzYWdlVXBkYXRlKSB7XG5cdCAgICAgICAgICAgIC8vIEFwcGVuZFxuXHQgICAgICAgICAgICB0aGlzLl9hcHBlbmQobWVzc2FnZVVwZGF0ZSk7XG5cblx0ICAgICAgICAgICAgLy8gVXBkYXRlIHRoZSBoYXNoXG5cdCAgICAgICAgICAgIHRoaXMuX3Byb2Nlc3MoKTtcblxuXHQgICAgICAgICAgICAvLyBDaGFpbmFibGVcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXM7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEZpbmFsaXplcyB0aGUgaGFzaCBjb21wdXRhdGlvbi5cblx0ICAgICAgICAgKiBOb3RlIHRoYXQgdGhlIGZpbmFsaXplIG9wZXJhdGlvbiBpcyBlZmZlY3RpdmVseSBhIGRlc3RydWN0aXZlLCByZWFkLW9uY2Ugb3BlcmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlVXBkYXRlIChPcHRpb25hbCkgQSBmaW5hbCBtZXNzYWdlIHVwZGF0ZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGhhc2guXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBoYXNoID0gaGFzaGVyLmZpbmFsaXplKCk7XG5cdCAgICAgICAgICogICAgIHZhciBoYXNoID0gaGFzaGVyLmZpbmFsaXplKCdtZXNzYWdlJyk7XG5cdCAgICAgICAgICogICAgIHZhciBoYXNoID0gaGFzaGVyLmZpbmFsaXplKHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgZmluYWxpemU6IGZ1bmN0aW9uIChtZXNzYWdlVXBkYXRlKSB7XG5cdCAgICAgICAgICAgIC8vIEZpbmFsIG1lc3NhZ2UgdXBkYXRlXG5cdCAgICAgICAgICAgIGlmIChtZXNzYWdlVXBkYXRlKSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9hcHBlbmQobWVzc2FnZVVwZGF0ZSk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBQZXJmb3JtIGNvbmNyZXRlLWhhc2hlciBsb2dpY1xuXHQgICAgICAgICAgICB2YXIgaGFzaCA9IHRoaXMuX2RvRmluYWxpemUoKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gaGFzaDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgYmxvY2tTaXplOiA1MTIvMzIsXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDcmVhdGVzIGEgc2hvcnRjdXQgZnVuY3Rpb24gdG8gYSBoYXNoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtIYXNoZXJ9IGhhc2hlciBUaGUgaGFzaGVyIHRvIGNyZWF0ZSBhIGhlbHBlciBmb3IuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtGdW5jdGlvbn0gVGhlIHNob3J0Y3V0IGZ1bmN0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgU0hBMjU2ID0gQ3J5cHRvSlMubGliLkhhc2hlci5fY3JlYXRlSGVscGVyKENyeXB0b0pTLmFsZ28uU0hBMjU2KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBfY3JlYXRlSGVscGVyOiBmdW5jdGlvbiAoaGFzaGVyKSB7XG5cdCAgICAgICAgICAgIHJldHVybiBmdW5jdGlvbiAobWVzc2FnZSwgY2ZnKSB7XG5cdCAgICAgICAgICAgICAgICByZXR1cm4gbmV3IGhhc2hlci5pbml0KGNmZykuZmluYWxpemUobWVzc2FnZSk7XG5cdCAgICAgICAgICAgIH07XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENyZWF0ZXMgYSBzaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgSE1BQydzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0hhc2hlcn0gaGFzaGVyIFRoZSBoYXNoZXIgdG8gdXNlIGluIHRoaXMgSE1BQyBoZWxwZXIuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtGdW5jdGlvbn0gVGhlIHNob3J0Y3V0IGZ1bmN0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgSG1hY1NIQTI1NiA9IENyeXB0b0pTLmxpYi5IYXNoZXIuX2NyZWF0ZUhtYWNIZWxwZXIoQ3J5cHRvSlMuYWxnby5TSEEyNTYpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIF9jcmVhdGVIbWFjSGVscGVyOiBmdW5jdGlvbiAoaGFzaGVyKSB7XG5cdCAgICAgICAgICAgIHJldHVybiBmdW5jdGlvbiAobWVzc2FnZSwga2V5KSB7XG5cdCAgICAgICAgICAgICAgICByZXR1cm4gbmV3IENfYWxnby5ITUFDLmluaXQoaGFzaGVyLCBrZXkpLmZpbmFsaXplKG1lc3NhZ2UpO1xuXHQgICAgICAgICAgICB9O1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEFsZ29yaXRobSBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ28gPSB7fTtcblxuXHQgICAgcmV0dXJuIEM7XG5cdH0oTWF0aCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5O1xuXHQgICAgdmFyIENfZW5jID0gQy5lbmM7XG5cblx0ICAgIC8qKlxuXHQgICAgICogQmFzZTY0IGVuY29kaW5nIHN0cmF0ZWd5LlxuXHQgICAgICovXG5cdCAgICB2YXIgQmFzZTY0ID0gQ19lbmMuQmFzZTY0ID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgd29yZCBhcnJheSB0byBhIEJhc2U2NCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gd29yZEFycmF5IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7c3RyaW5nfSBUaGUgQmFzZTY0IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGJhc2U2NFN0cmluZyA9IENyeXB0b0pTLmVuYy5CYXNlNjQuc3RyaW5naWZ5KHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgc3RyaW5naWZ5OiBmdW5jdGlvbiAod29yZEFycmF5KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSB3b3JkQXJyYXkud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBzaWdCeXRlcyA9IHdvcmRBcnJheS5zaWdCeXRlcztcblx0ICAgICAgICAgICAgdmFyIG1hcCA9IHRoaXMuX21hcDtcblxuXHQgICAgICAgICAgICAvLyBDbGFtcCBleGNlc3MgYml0c1xuXHQgICAgICAgICAgICB3b3JkQXJyYXkuY2xhbXAoKTtcblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0XG5cdCAgICAgICAgICAgIHZhciBiYXNlNjRDaGFycyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHNpZ0J5dGVzOyBpICs9IDMpIHtcblx0ICAgICAgICAgICAgICAgIHZhciBieXRlMSA9ICh3b3Jkc1tpID4+PiAyXSAgICAgICA+Pj4gKDI0IC0gKGkgJSA0KSAqIDgpKSAgICAgICAmIDB4ZmY7XG5cdCAgICAgICAgICAgICAgICB2YXIgYnl0ZTIgPSAod29yZHNbKGkgKyAxKSA+Pj4gMl0gPj4+ICgyNCAtICgoaSArIDEpICUgNCkgKiA4KSkgJiAweGZmO1xuXHQgICAgICAgICAgICAgICAgdmFyIGJ5dGUzID0gKHdvcmRzWyhpICsgMikgPj4+IDJdID4+PiAoMjQgLSAoKGkgKyAyKSAlIDQpICogOCkpICYgMHhmZjtcblxuXHQgICAgICAgICAgICAgICAgdmFyIHRyaXBsZXQgPSAoYnl0ZTEgPDwgMTYpIHwgKGJ5dGUyIDw8IDgpIHwgYnl0ZTM7XG5cblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyAoaiA8IDQpICYmIChpICsgaiAqIDAuNzUgPCBzaWdCeXRlcyk7IGorKykge1xuXHQgICAgICAgICAgICAgICAgICAgIGJhc2U2NENoYXJzLnB1c2gobWFwLmNoYXJBdCgodHJpcGxldCA+Pj4gKDYgKiAoMyAtIGopKSkgJiAweDNmKSk7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBBZGQgcGFkZGluZ1xuXHQgICAgICAgICAgICB2YXIgcGFkZGluZ0NoYXIgPSBtYXAuY2hhckF0KDY0KTtcblx0ICAgICAgICAgICAgaWYgKHBhZGRpbmdDaGFyKSB7XG5cdCAgICAgICAgICAgICAgICB3aGlsZSAoYmFzZTY0Q2hhcnMubGVuZ3RoICUgNCkge1xuXHQgICAgICAgICAgICAgICAgICAgIGJhc2U2NENoYXJzLnB1c2gocGFkZGluZ0NoYXIpO1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGJhc2U2NENoYXJzLmpvaW4oJycpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyBhIEJhc2U2NCBzdHJpbmcgdG8gYSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtzdHJpbmd9IGJhc2U2NFN0ciBUaGUgQmFzZTY0IHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAc3RhdGljXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy5lbmMuQmFzZTY0LnBhcnNlKGJhc2U2NFN0cmluZyk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcGFyc2U6IGZ1bmN0aW9uIChiYXNlNjRTdHIpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBiYXNlNjRTdHJMZW5ndGggPSBiYXNlNjRTdHIubGVuZ3RoO1xuXHQgICAgICAgICAgICB2YXIgbWFwID0gdGhpcy5fbWFwO1xuXHQgICAgICAgICAgICB2YXIgcmV2ZXJzZU1hcCA9IHRoaXMuX3JldmVyc2VNYXA7XG5cblx0ICAgICAgICAgICAgaWYgKCFyZXZlcnNlTWFwKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgcmV2ZXJzZU1hcCA9IHRoaXMuX3JldmVyc2VNYXAgPSBbXTtcblx0ICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IG1hcC5sZW5ndGg7IGorKykge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICByZXZlcnNlTWFwW21hcC5jaGFyQ29kZUF0KGopXSA9IGo7XG5cdCAgICAgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gSWdub3JlIHBhZGRpbmdcblx0ICAgICAgICAgICAgdmFyIHBhZGRpbmdDaGFyID0gbWFwLmNoYXJBdCg2NCk7XG5cdCAgICAgICAgICAgIGlmIChwYWRkaW5nQ2hhcikge1xuXHQgICAgICAgICAgICAgICAgdmFyIHBhZGRpbmdJbmRleCA9IGJhc2U2NFN0ci5pbmRleE9mKHBhZGRpbmdDaGFyKTtcblx0ICAgICAgICAgICAgICAgIGlmIChwYWRkaW5nSW5kZXggIT09IC0xKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgYmFzZTY0U3RyTGVuZ3RoID0gcGFkZGluZ0luZGV4O1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydFxuXHQgICAgICAgICAgICByZXR1cm4gcGFyc2VMb29wKGJhc2U2NFN0ciwgYmFzZTY0U3RyTGVuZ3RoLCByZXZlcnNlTWFwKTtcblxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfbWFwOiAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODkrLz0nXG5cdCAgICB9O1xuXG5cdCAgICBmdW5jdGlvbiBwYXJzZUxvb3AoYmFzZTY0U3RyLCBiYXNlNjRTdHJMZW5ndGgsIHJldmVyc2VNYXApIHtcblx0ICAgICAgdmFyIHdvcmRzID0gW107XG5cdCAgICAgIHZhciBuQnl0ZXMgPSAwO1xuXHQgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJhc2U2NFN0ckxlbmd0aDsgaSsrKSB7XG5cdCAgICAgICAgICBpZiAoaSAlIDQpIHtcblx0ICAgICAgICAgICAgICB2YXIgYml0czEgPSByZXZlcnNlTWFwW2Jhc2U2NFN0ci5jaGFyQ29kZUF0KGkgLSAxKV0gPDwgKChpICUgNCkgKiAyKTtcblx0ICAgICAgICAgICAgICB2YXIgYml0czIgPSByZXZlcnNlTWFwW2Jhc2U2NFN0ci5jaGFyQ29kZUF0KGkpXSA+Pj4gKDYgLSAoaSAlIDQpICogMik7XG5cdCAgICAgICAgICAgICAgd29yZHNbbkJ5dGVzID4+PiAyXSB8PSAoYml0czEgfCBiaXRzMikgPDwgKDI0IC0gKG5CeXRlcyAlIDQpICogOCk7XG5cdCAgICAgICAgICAgICAgbkJ5dGVzKys7XG5cdCAgICAgICAgICB9XG5cdCAgICAgIH1cblx0ICAgICAgcmV0dXJuIFdvcmRBcnJheS5jcmVhdGUod29yZHMsIG5CeXRlcyk7XG5cdCAgICB9XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuZW5jLkJhc2U2NDtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uICgpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIFdvcmRBcnJheSA9IENfbGliLldvcmRBcnJheTtcblx0ICAgIHZhciBDX2VuYyA9IEMuZW5jO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFVURi0xNiBCRSBlbmNvZGluZyBzdHJhdGVneS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFV0ZjE2QkUgPSBDX2VuYy5VdGYxNiA9IENfZW5jLlV0ZjE2QkUgPSB7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29udmVydHMgYSB3b3JkIGFycmF5IHRvIGEgVVRGLTE2IEJFIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fSB3b3JkQXJyYXkgVGhlIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBVVEYtMTYgQkUgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgdXRmMTZTdHJpbmcgPSBDcnlwdG9KUy5lbmMuVXRmMTYuc3RyaW5naWZ5KHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgc3RyaW5naWZ5OiBmdW5jdGlvbiAod29yZEFycmF5KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSB3b3JkQXJyYXkud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBzaWdCeXRlcyA9IHdvcmRBcnJheS5zaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0XG5cdCAgICAgICAgICAgIHZhciB1dGYxNkNoYXJzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2lnQnl0ZXM7IGkgKz0gMikge1xuXHQgICAgICAgICAgICAgICAgdmFyIGNvZGVQb2ludCA9ICh3b3Jkc1tpID4+PiAyXSA+Pj4gKDE2IC0gKGkgJSA0KSAqIDgpKSAmIDB4ZmZmZjtcblx0ICAgICAgICAgICAgICAgIHV0ZjE2Q2hhcnMucHVzaChTdHJpbmcuZnJvbUNoYXJDb2RlKGNvZGVQb2ludCkpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIHV0ZjE2Q2hhcnMuam9pbignJyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgVVRGLTE2IEJFIHN0cmluZyB0byBhIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gdXRmMTZTdHIgVGhlIFVURi0xNiBCRSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMuZW5jLlV0ZjE2LnBhcnNlKHV0ZjE2U3RyaW5nKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBwYXJzZTogZnVuY3Rpb24gKHV0ZjE2U3RyKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciB1dGYxNlN0ckxlbmd0aCA9IHV0ZjE2U3RyLmxlbmd0aDtcblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0XG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHV0ZjE2U3RyTGVuZ3RoOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHdvcmRzW2kgPj4+IDFdIHw9IHV0ZjE2U3RyLmNoYXJDb2RlQXQoaSkgPDwgKDE2IC0gKGkgJSAyKSAqIDE2KTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiBXb3JkQXJyYXkuY3JlYXRlKHdvcmRzLCB1dGYxNlN0ckxlbmd0aCAqIDIpO1xuXHQgICAgICAgIH1cblx0ICAgIH07XG5cblx0ICAgIC8qKlxuXHQgICAgICogVVRGLTE2IExFIGVuY29kaW5nIHN0cmF0ZWd5LlxuXHQgICAgICovXG5cdCAgICBDX2VuYy5VdGYxNkxFID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgd29yZCBhcnJheSB0byBhIFVURi0xNiBMRSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheX0gd29yZEFycmF5IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7c3RyaW5nfSBUaGUgVVRGLTE2IExFIHN0cmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHV0ZjE2U3RyID0gQ3J5cHRvSlMuZW5jLlV0ZjE2TEUuc3RyaW5naWZ5KHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgc3RyaW5naWZ5OiBmdW5jdGlvbiAod29yZEFycmF5KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSB3b3JkQXJyYXkud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBzaWdCeXRlcyA9IHdvcmRBcnJheS5zaWdCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBDb252ZXJ0XG5cdCAgICAgICAgICAgIHZhciB1dGYxNkNoYXJzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2lnQnl0ZXM7IGkgKz0gMikge1xuXHQgICAgICAgICAgICAgICAgdmFyIGNvZGVQb2ludCA9IHN3YXBFbmRpYW4oKHdvcmRzW2kgPj4+IDJdID4+PiAoMTYgLSAoaSAlIDQpICogOCkpICYgMHhmZmZmKTtcblx0ICAgICAgICAgICAgICAgIHV0ZjE2Q2hhcnMucHVzaChTdHJpbmcuZnJvbUNoYXJDb2RlKGNvZGVQb2ludCkpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIHV0ZjE2Q2hhcnMuam9pbignJyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgVVRGLTE2IExFIHN0cmluZyB0byBhIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gdXRmMTZTdHIgVGhlIFVURi0xNiBMRSBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSB3b3JkIGFycmF5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgd29yZEFycmF5ID0gQ3J5cHRvSlMuZW5jLlV0ZjE2TEUucGFyc2UodXRmMTZTdHIpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHBhcnNlOiBmdW5jdGlvbiAodXRmMTZTdHIpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIHV0ZjE2U3RyTGVuZ3RoID0gdXRmMTZTdHIubGVuZ3RoO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIHdvcmRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdXRmMTZTdHJMZW5ndGg7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbaSA+Pj4gMV0gfD0gc3dhcEVuZGlhbih1dGYxNlN0ci5jaGFyQ29kZUF0KGkpIDw8ICgxNiAtIChpICUgMikgKiAxNikpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIFdvcmRBcnJheS5jcmVhdGUod29yZHMsIHV0ZjE2U3RyTGVuZ3RoICogMik7XG5cdCAgICAgICAgfVxuXHQgICAgfTtcblxuXHQgICAgZnVuY3Rpb24gc3dhcEVuZGlhbih3b3JkKSB7XG5cdCAgICAgICAgcmV0dXJuICgod29yZCA8PCA4KSAmIDB4ZmYwMGZmMDApIHwgKCh3b3JkID4+PiA4KSAmIDB4MDBmZjAwZmYpO1xuXHQgICAgfVxuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLmVuYy5VdGYxNjtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9zaGExXCIpLCByZXF1aXJlKFwiLi9obWFjXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL3NoYTFcIiwgXCIuL2htYWNcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBCYXNlID0gQ19saWIuQmFzZTtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXHQgICAgdmFyIE1ENSA9IENfYWxnby5NRDU7XG5cblx0ICAgIC8qKlxuXHQgICAgICogVGhpcyBrZXkgZGVyaXZhdGlvbiBmdW5jdGlvbiBpcyBtZWFudCB0byBjb25mb3JtIHdpdGggRVZQX0J5dGVzVG9LZXkuXG5cdCAgICAgKiB3d3cub3BlbnNzbC5vcmcvZG9jcy9jcnlwdG8vRVZQX0J5dGVzVG9LZXkuaHRtbFxuXHQgICAgICovXG5cdCAgICB2YXIgRXZwS0RGID0gQ19hbGdvLkV2cEtERiA9IEJhc2UuZXh0ZW5kKHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb25maWd1cmF0aW9uIG9wdGlvbnMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcHJvcGVydHkge251bWJlcn0ga2V5U2l6ZSBUaGUga2V5IHNpemUgaW4gd29yZHMgdG8gZ2VuZXJhdGUuIERlZmF1bHQ6IDQgKDEyOCBiaXRzKVxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7SGFzaGVyfSBoYXNoZXIgVGhlIGhhc2ggYWxnb3JpdGhtIHRvIHVzZS4gRGVmYXVsdDogTUQ1XG5cdCAgICAgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IGl0ZXJhdGlvbnMgVGhlIG51bWJlciBvZiBpdGVyYXRpb25zIHRvIHBlcmZvcm0uIERlZmF1bHQ6IDFcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjZmc6IEJhc2UuZXh0ZW5kKHtcblx0ICAgICAgICAgICAga2V5U2l6ZTogMTI4LzMyLFxuXHQgICAgICAgICAgICBoYXNoZXI6IE1ENSxcblx0ICAgICAgICAgICAgaXRlcmF0aW9uczogMVxuXHQgICAgICAgIH0pLFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogSW5pdGlhbGl6ZXMgYSBuZXdseSBjcmVhdGVkIGtleSBkZXJpdmF0aW9uIGZ1bmN0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGUgZGVyaXZhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGtkZiA9IENyeXB0b0pTLmFsZ28uRXZwS0RGLmNyZWF0ZSgpO1xuXHQgICAgICAgICAqICAgICB2YXIga2RmID0gQ3J5cHRvSlMuYWxnby5FdnBLREYuY3JlYXRlKHsga2V5U2l6ZTogOCB9KTtcblx0ICAgICAgICAgKiAgICAgdmFyIGtkZiA9IENyeXB0b0pTLmFsZ28uRXZwS0RGLmNyZWF0ZSh7IGtleVNpemU6IDgsIGl0ZXJhdGlvbnM6IDEwMDAgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKGNmZykge1xuXHQgICAgICAgICAgICB0aGlzLmNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBEZXJpdmVzIGEga2V5IGZyb20gYSBwYXNzd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gcGFzc3dvcmQgVGhlIHBhc3N3b3JkLlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gc2FsdCBBIHNhbHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBkZXJpdmVkIGtleS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGtleSA9IGtkZi5jb21wdXRlKHBhc3N3b3JkLCBzYWx0KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjb21wdXRlOiBmdW5jdGlvbiAocGFzc3dvcmQsIHNhbHQpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGNmZyA9IHRoaXMuY2ZnO1xuXG5cdCAgICAgICAgICAgIC8vIEluaXQgaGFzaGVyXG5cdCAgICAgICAgICAgIHZhciBoYXNoZXIgPSBjZmcuaGFzaGVyLmNyZWF0ZSgpO1xuXG5cdCAgICAgICAgICAgIC8vIEluaXRpYWwgdmFsdWVzXG5cdCAgICAgICAgICAgIHZhciBkZXJpdmVkS2V5ID0gV29yZEFycmF5LmNyZWF0ZSgpO1xuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgZGVyaXZlZEtleVdvcmRzID0gZGVyaXZlZEtleS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIGtleVNpemUgPSBjZmcua2V5U2l6ZTtcblx0ICAgICAgICAgICAgdmFyIGl0ZXJhdGlvbnMgPSBjZmcuaXRlcmF0aW9ucztcblxuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSBrZXlcblx0ICAgICAgICAgICAgd2hpbGUgKGRlcml2ZWRLZXlXb3Jkcy5sZW5ndGggPCBrZXlTaXplKSB7XG5cdCAgICAgICAgICAgICAgICBpZiAoYmxvY2spIHtcblx0ICAgICAgICAgICAgICAgICAgICBoYXNoZXIudXBkYXRlKGJsb2NrKTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIHZhciBibG9jayA9IGhhc2hlci51cGRhdGUocGFzc3dvcmQpLmZpbmFsaXplKHNhbHQpO1xuXHQgICAgICAgICAgICAgICAgaGFzaGVyLnJlc2V0KCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIEl0ZXJhdGlvbnNcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAxOyBpIDwgaXRlcmF0aW9uczsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgYmxvY2sgPSBoYXNoZXIuZmluYWxpemUoYmxvY2spO1xuXHQgICAgICAgICAgICAgICAgICAgIGhhc2hlci5yZXNldCgpO1xuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICBkZXJpdmVkS2V5LmNvbmNhdChibG9jayk7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgZGVyaXZlZEtleS5zaWdCeXRlcyA9IGtleVNpemUgKiA0O1xuXG5cdCAgICAgICAgICAgIHJldHVybiBkZXJpdmVkS2V5O1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIERlcml2ZXMgYSBrZXkgZnJvbSBhIHBhc3N3b3JkLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gcGFzc3dvcmQgVGhlIHBhc3N3b3JkLlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBzYWx0IEEgc2FsdC5cblx0ICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBjb21wdXRhdGlvbi5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBkZXJpdmVkIGtleS5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGtleSA9IENyeXB0b0pTLkV2cEtERihwYXNzd29yZCwgc2FsdCk7XG5cdCAgICAgKiAgICAgdmFyIGtleSA9IENyeXB0b0pTLkV2cEtERihwYXNzd29yZCwgc2FsdCwgeyBrZXlTaXplOiA4IH0pO1xuXHQgICAgICogICAgIHZhciBrZXkgPSBDcnlwdG9KUy5FdnBLREYocGFzc3dvcmQsIHNhbHQsIHsga2V5U2l6ZTogOCwgaXRlcmF0aW9uczogMTAwMCB9KTtcblx0ICAgICAqL1xuXHQgICAgQy5FdnBLREYgPSBmdW5jdGlvbiAocGFzc3dvcmQsIHNhbHQsIGNmZykge1xuXHQgICAgICAgIHJldHVybiBFdnBLREYuY3JlYXRlKGNmZykuY29tcHV0ZShwYXNzd29yZCwgc2FsdCk7XG5cdCAgICB9O1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLkV2cEtERjtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9jaXBoZXItY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uICh1bmRlZmluZWQpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIENpcGhlclBhcmFtcyA9IENfbGliLkNpcGhlclBhcmFtcztcblx0ICAgIHZhciBDX2VuYyA9IEMuZW5jO1xuXHQgICAgdmFyIEhleCA9IENfZW5jLkhleDtcblx0ICAgIHZhciBDX2Zvcm1hdCA9IEMuZm9ybWF0O1xuXG5cdCAgICB2YXIgSGV4Rm9ybWF0dGVyID0gQ19mb3JtYXQuSGV4ID0ge1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIHRoZSBjaXBoZXJ0ZXh0IG9mIGEgY2lwaGVyIHBhcmFtcyBvYmplY3QgdG8gYSBoZXhhZGVjaW1hbGx5IGVuY29kZWQgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtDaXBoZXJQYXJhbXN9IGNpcGhlclBhcmFtcyBUaGUgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtzdHJpbmd9IFRoZSBoZXhhZGVjaW1hbGx5IGVuY29kZWQgc3RyaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHN0YXRpY1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgaGV4U3RyaW5nID0gQ3J5cHRvSlMuZm9ybWF0LkhleC5zdHJpbmdpZnkoY2lwaGVyUGFyYW1zKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBzdHJpbmdpZnk6IGZ1bmN0aW9uIChjaXBoZXJQYXJhbXMpIHtcblx0ICAgICAgICAgICAgcmV0dXJuIGNpcGhlclBhcmFtcy5jaXBoZXJ0ZXh0LnRvU3RyaW5nKEhleCk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIENvbnZlcnRzIGEgaGV4YWRlY2ltYWxseSBlbmNvZGVkIGNpcGhlcnRleHQgc3RyaW5nIHRvIGEgY2lwaGVyIHBhcmFtcyBvYmplY3QuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge3N0cmluZ30gaW5wdXQgVGhlIGhleGFkZWNpbWFsbHkgZW5jb2RlZCBzdHJpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDaXBoZXJQYXJhbXN9IFRoZSBjaXBoZXIgcGFyYW1zIG9iamVjdC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBzdGF0aWNcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNpcGhlclBhcmFtcyA9IENyeXB0b0pTLmZvcm1hdC5IZXgucGFyc2UoaGV4U3RyaW5nKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBwYXJzZTogZnVuY3Rpb24gKGlucHV0KSB7XG5cdCAgICAgICAgICAgIHZhciBjaXBoZXJ0ZXh0ID0gSGV4LnBhcnNlKGlucHV0KTtcblx0ICAgICAgICAgICAgcmV0dXJuIENpcGhlclBhcmFtcy5jcmVhdGUoeyBjaXBoZXJ0ZXh0OiBjaXBoZXJ0ZXh0IH0pO1xuXHQgICAgICAgIH1cblx0ICAgIH07XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuZm9ybWF0LkhleDtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uICgpIHtcblx0ICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgdmFyIEMgPSBDcnlwdG9KUztcblx0ICAgIHZhciBDX2xpYiA9IEMubGliO1xuXHQgICAgdmFyIEJhc2UgPSBDX2xpYi5CYXNlO1xuXHQgICAgdmFyIENfZW5jID0gQy5lbmM7XG5cdCAgICB2YXIgVXRmOCA9IENfZW5jLlV0Zjg7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICAvKipcblx0ICAgICAqIEhNQUMgYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgSE1BQyA9IENfYWxnby5ITUFDID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCBITUFDLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtIYXNoZXJ9IGhhc2hlciBUaGUgaGFzaCBhbGdvcml0aG0gdG8gdXNlLlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30ga2V5IFRoZSBzZWNyZXQga2V5LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgaG1hY0hhc2hlciA9IENyeXB0b0pTLmFsZ28uSE1BQy5jcmVhdGUoQ3J5cHRvSlMuYWxnby5TSEEyNTYsIGtleSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKGhhc2hlciwga2V5KSB7XG5cdCAgICAgICAgICAgIC8vIEluaXQgaGFzaGVyXG5cdCAgICAgICAgICAgIGhhc2hlciA9IHRoaXMuX2hhc2hlciA9IG5ldyBoYXNoZXIuaW5pdCgpO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnQgc3RyaW5nIHRvIFdvcmRBcnJheSwgZWxzZSBhc3N1bWUgV29yZEFycmF5IGFscmVhZHlcblx0ICAgICAgICAgICAgaWYgKHR5cGVvZiBrZXkgPT0gJ3N0cmluZycpIHtcblx0ICAgICAgICAgICAgICAgIGtleSA9IFV0ZjgucGFyc2Uoa2V5KTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgaGFzaGVyQmxvY2tTaXplID0gaGFzaGVyLmJsb2NrU2l6ZTtcblx0ICAgICAgICAgICAgdmFyIGhhc2hlckJsb2NrU2l6ZUJ5dGVzID0gaGFzaGVyQmxvY2tTaXplICogNDtcblxuXHQgICAgICAgICAgICAvLyBBbGxvdyBhcmJpdHJhcnkgbGVuZ3RoIGtleXNcblx0ICAgICAgICAgICAgaWYgKGtleS5zaWdCeXRlcyA+IGhhc2hlckJsb2NrU2l6ZUJ5dGVzKSB7XG5cdCAgICAgICAgICAgICAgICBrZXkgPSBoYXNoZXIuZmluYWxpemUoa2V5KTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIENsYW1wIGV4Y2VzcyBiaXRzXG5cdCAgICAgICAgICAgIGtleS5jbGFtcCgpO1xuXG5cdCAgICAgICAgICAgIC8vIENsb25lIGtleSBmb3IgaW5uZXIgYW5kIG91dGVyIHBhZHNcblx0ICAgICAgICAgICAgdmFyIG9LZXkgPSB0aGlzLl9vS2V5ID0ga2V5LmNsb25lKCk7XG5cdCAgICAgICAgICAgIHZhciBpS2V5ID0gdGhpcy5faUtleSA9IGtleS5jbG9uZSgpO1xuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgb0tleVdvcmRzID0gb0tleS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIGlLZXlXb3JkcyA9IGlLZXkud29yZHM7XG5cblx0ICAgICAgICAgICAgLy8gWE9SIGtleXMgd2l0aCBwYWQgY29uc3RhbnRzXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaGFzaGVyQmxvY2tTaXplOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIG9LZXlXb3Jkc1tpXSBePSAweDVjNWM1YzVjO1xuXHQgICAgICAgICAgICAgICAgaUtleVdvcmRzW2ldIF49IDB4MzYzNjM2MzY7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgb0tleS5zaWdCeXRlcyA9IGlLZXkuc2lnQnl0ZXMgPSBoYXNoZXJCbG9ja1NpemVCeXRlcztcblxuXHQgICAgICAgICAgICAvLyBTZXQgaW5pdGlhbCB2YWx1ZXNcblx0ICAgICAgICAgICAgdGhpcy5yZXNldCgpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBSZXNldHMgdGhpcyBITUFDIHRvIGl0cyBpbml0aWFsIHN0YXRlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBobWFjSGFzaGVyLnJlc2V0KCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgcmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGhhc2hlciA9IHRoaXMuX2hhc2hlcjtcblxuXHQgICAgICAgICAgICAvLyBSZXNldFxuXHQgICAgICAgICAgICBoYXNoZXIucmVzZXQoKTtcblx0ICAgICAgICAgICAgaGFzaGVyLnVwZGF0ZSh0aGlzLl9pS2V5KTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogVXBkYXRlcyB0aGlzIEhNQUMgd2l0aCBhIG1lc3NhZ2UuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2VVcGRhdGUgVGhlIG1lc3NhZ2UgdG8gYXBwZW5kLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7SE1BQ30gVGhpcyBITUFDIGluc3RhbmNlLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICBobWFjSGFzaGVyLnVwZGF0ZSgnbWVzc2FnZScpO1xuXHQgICAgICAgICAqICAgICBobWFjSGFzaGVyLnVwZGF0ZSh3b3JkQXJyYXkpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIHVwZGF0ZTogZnVuY3Rpb24gKG1lc3NhZ2VVcGRhdGUpIHtcblx0ICAgICAgICAgICAgdGhpcy5faGFzaGVyLnVwZGF0ZShtZXNzYWdlVXBkYXRlKTtcblxuXHQgICAgICAgICAgICAvLyBDaGFpbmFibGVcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXM7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEZpbmFsaXplcyB0aGUgSE1BQyBjb21wdXRhdGlvbi5cblx0ICAgICAgICAgKiBOb3RlIHRoYXQgdGhlIGZpbmFsaXplIG9wZXJhdGlvbiBpcyBlZmZlY3RpdmVseSBhIGRlc3RydWN0aXZlLCByZWFkLW9uY2Ugb3BlcmF0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlVXBkYXRlIChPcHRpb25hbCkgQSBmaW5hbCBtZXNzYWdlIHVwZGF0ZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIEhNQUMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBobWFjID0gaG1hY0hhc2hlci5maW5hbGl6ZSgpO1xuXHQgICAgICAgICAqICAgICB2YXIgaG1hYyA9IGhtYWNIYXNoZXIuZmluYWxpemUoJ21lc3NhZ2UnKTtcblx0ICAgICAgICAgKiAgICAgdmFyIGhtYWMgPSBobWFjSGFzaGVyLmZpbmFsaXplKHdvcmRBcnJheSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgZmluYWxpemU6IGZ1bmN0aW9uIChtZXNzYWdlVXBkYXRlKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciBoYXNoZXIgPSB0aGlzLl9oYXNoZXI7XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0ZSBITUFDXG5cdCAgICAgICAgICAgIHZhciBpbm5lckhhc2ggPSBoYXNoZXIuZmluYWxpemUobWVzc2FnZVVwZGF0ZSk7XG5cdCAgICAgICAgICAgIGhhc2hlci5yZXNldCgpO1xuXHQgICAgICAgICAgICB2YXIgaG1hYyA9IGhhc2hlci5maW5hbGl6ZSh0aGlzLl9vS2V5LmNsb25lKCkuY29uY2F0KGlubmVySGFzaCkpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBobWFjO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXHR9KCkpO1xuXG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4veDY0LWNvcmVcIiksIHJlcXVpcmUoXCIuL2xpYi10eXBlZGFycmF5c1wiKSwgcmVxdWlyZShcIi4vZW5jLXV0ZjE2XCIpLCByZXF1aXJlKFwiLi9lbmMtYmFzZTY0XCIpLCByZXF1aXJlKFwiLi9tZDVcIiksIHJlcXVpcmUoXCIuL3NoYTFcIiksIHJlcXVpcmUoXCIuL3NoYTI1NlwiKSwgcmVxdWlyZShcIi4vc2hhMjI0XCIpLCByZXF1aXJlKFwiLi9zaGE1MTJcIiksIHJlcXVpcmUoXCIuL3NoYTM4NFwiKSwgcmVxdWlyZShcIi4vc2hhM1wiKSwgcmVxdWlyZShcIi4vcmlwZW1kMTYwXCIpLCByZXF1aXJlKFwiLi9obWFjXCIpLCByZXF1aXJlKFwiLi9wYmtkZjJcIiksIHJlcXVpcmUoXCIuL2V2cGtkZlwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIiksIHJlcXVpcmUoXCIuL21vZGUtY2ZiXCIpLCByZXF1aXJlKFwiLi9tb2RlLWN0clwiKSwgcmVxdWlyZShcIi4vbW9kZS1jdHItZ2xhZG1hblwiKSwgcmVxdWlyZShcIi4vbW9kZS1vZmJcIiksIHJlcXVpcmUoXCIuL21vZGUtZWNiXCIpLCByZXF1aXJlKFwiLi9wYWQtYW5zaXg5MjNcIiksIHJlcXVpcmUoXCIuL3BhZC1pc28xMDEyNlwiKSwgcmVxdWlyZShcIi4vcGFkLWlzbzk3OTcxXCIpLCByZXF1aXJlKFwiLi9wYWQtemVyb3BhZGRpbmdcIiksIHJlcXVpcmUoXCIuL3BhZC1ub3BhZGRpbmdcIiksIHJlcXVpcmUoXCIuL2Zvcm1hdC1oZXhcIiksIHJlcXVpcmUoXCIuL2Flc1wiKSwgcmVxdWlyZShcIi4vdHJpcGxlZGVzXCIpLCByZXF1aXJlKFwiLi9yYzRcIiksIHJlcXVpcmUoXCIuL3JhYmJpdFwiKSwgcmVxdWlyZShcIi4vcmFiYml0LWxlZ2FjeVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi94NjQtY29yZVwiLCBcIi4vbGliLXR5cGVkYXJyYXlzXCIsIFwiLi9lbmMtdXRmMTZcIiwgXCIuL2VuYy1iYXNlNjRcIiwgXCIuL21kNVwiLCBcIi4vc2hhMVwiLCBcIi4vc2hhMjU2XCIsIFwiLi9zaGEyMjRcIiwgXCIuL3NoYTUxMlwiLCBcIi4vc2hhMzg0XCIsIFwiLi9zaGEzXCIsIFwiLi9yaXBlbWQxNjBcIiwgXCIuL2htYWNcIiwgXCIuL3Bia2RmMlwiLCBcIi4vZXZwa2RmXCIsIFwiLi9jaXBoZXItY29yZVwiLCBcIi4vbW9kZS1jZmJcIiwgXCIuL21vZGUtY3RyXCIsIFwiLi9tb2RlLWN0ci1nbGFkbWFuXCIsIFwiLi9tb2RlLW9mYlwiLCBcIi4vbW9kZS1lY2JcIiwgXCIuL3BhZC1hbnNpeDkyM1wiLCBcIi4vcGFkLWlzbzEwMTI2XCIsIFwiLi9wYWQtaXNvOTc5NzFcIiwgXCIuL3BhZC16ZXJvcGFkZGluZ1wiLCBcIi4vcGFkLW5vcGFkZGluZ1wiLCBcIi4vZm9ybWF0LWhleFwiLCBcIi4vYWVzXCIsIFwiLi90cmlwbGVkZXNcIiwgXCIuL3JjNFwiLCBcIi4vcmFiYml0XCIsIFwiLi9yYWJiaXQtbGVnYWN5XCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0cm9vdC5DcnlwdG9KUyA9IGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0cmV0dXJuIENyeXB0b0pTO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gQ2hlY2sgaWYgdHlwZWQgYXJyYXlzIGFyZSBzdXBwb3J0ZWRcblx0ICAgIGlmICh0eXBlb2YgQXJyYXlCdWZmZXIgIT0gJ2Z1bmN0aW9uJykge1xuXHQgICAgICAgIHJldHVybjtcblx0ICAgIH1cblxuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5O1xuXG5cdCAgICAvLyBSZWZlcmVuY2Ugb3JpZ2luYWwgaW5pdFxuXHQgICAgdmFyIHN1cGVySW5pdCA9IFdvcmRBcnJheS5pbml0O1xuXG5cdCAgICAvLyBBdWdtZW50IFdvcmRBcnJheS5pbml0IHRvIGhhbmRsZSB0eXBlZCBhcnJheXNcblx0ICAgIHZhciBzdWJJbml0ID0gV29yZEFycmF5LmluaXQgPSBmdW5jdGlvbiAodHlwZWRBcnJheSkge1xuXHQgICAgICAgIC8vIENvbnZlcnQgYnVmZmVycyB0byB1aW50OFxuXHQgICAgICAgIGlmICh0eXBlZEFycmF5IGluc3RhbmNlb2YgQXJyYXlCdWZmZXIpIHtcblx0ICAgICAgICAgICAgdHlwZWRBcnJheSA9IG5ldyBVaW50OEFycmF5KHR5cGVkQXJyYXkpO1xuXHQgICAgICAgIH1cblxuXHQgICAgICAgIC8vIENvbnZlcnQgb3RoZXIgYXJyYXkgdmlld3MgdG8gdWludDhcblx0ICAgICAgICBpZiAoXG5cdCAgICAgICAgICAgIHR5cGVkQXJyYXkgaW5zdGFuY2VvZiBJbnQ4QXJyYXkgfHxcblx0ICAgICAgICAgICAgKHR5cGVvZiBVaW50OENsYW1wZWRBcnJheSAhPT0gXCJ1bmRlZmluZWRcIiAmJiB0eXBlZEFycmF5IGluc3RhbmNlb2YgVWludDhDbGFtcGVkQXJyYXkpIHx8XG5cdCAgICAgICAgICAgIHR5cGVkQXJyYXkgaW5zdGFuY2VvZiBJbnQxNkFycmF5IHx8XG5cdCAgICAgICAgICAgIHR5cGVkQXJyYXkgaW5zdGFuY2VvZiBVaW50MTZBcnJheSB8fFxuXHQgICAgICAgICAgICB0eXBlZEFycmF5IGluc3RhbmNlb2YgSW50MzJBcnJheSB8fFxuXHQgICAgICAgICAgICB0eXBlZEFycmF5IGluc3RhbmNlb2YgVWludDMyQXJyYXkgfHxcblx0ICAgICAgICAgICAgdHlwZWRBcnJheSBpbnN0YW5jZW9mIEZsb2F0MzJBcnJheSB8fFxuXHQgICAgICAgICAgICB0eXBlZEFycmF5IGluc3RhbmNlb2YgRmxvYXQ2NEFycmF5XG5cdCAgICAgICAgKSB7XG5cdCAgICAgICAgICAgIHR5cGVkQXJyYXkgPSBuZXcgVWludDhBcnJheSh0eXBlZEFycmF5LmJ1ZmZlciwgdHlwZWRBcnJheS5ieXRlT2Zmc2V0LCB0eXBlZEFycmF5LmJ5dGVMZW5ndGgpO1xuXHQgICAgICAgIH1cblxuXHQgICAgICAgIC8vIEhhbmRsZSBVaW50OEFycmF5XG5cdCAgICAgICAgaWYgKHR5cGVkQXJyYXkgaW5zdGFuY2VvZiBVaW50OEFycmF5KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgIHZhciB0eXBlZEFycmF5Qnl0ZUxlbmd0aCA9IHR5cGVkQXJyYXkuYnl0ZUxlbmd0aDtcblxuXHQgICAgICAgICAgICAvLyBFeHRyYWN0IGJ5dGVzXG5cdCAgICAgICAgICAgIHZhciB3b3JkcyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHR5cGVkQXJyYXlCeXRlTGVuZ3RoOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHdvcmRzW2kgPj4+IDJdIHw9IHR5cGVkQXJyYXlbaV0gPDwgKDI0IC0gKGkgJSA0KSAqIDgpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gSW5pdGlhbGl6ZSB0aGlzIHdvcmQgYXJyYXlcblx0ICAgICAgICAgICAgc3VwZXJJbml0LmNhbGwodGhpcywgd29yZHMsIHR5cGVkQXJyYXlCeXRlTGVuZ3RoKTtcblx0ICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAvLyBFbHNlIGNhbGwgbm9ybWFsIGluaXRcblx0ICAgICAgICAgICAgc3VwZXJJbml0LmFwcGx5KHRoaXMsIGFyZ3VtZW50cyk7XG5cdCAgICAgICAgfVxuXHQgICAgfTtcblxuXHQgICAgc3ViSW5pdC5wcm90b3R5cGUgPSBXb3JkQXJyYXk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMubGliLldvcmRBcnJheTtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uIChNYXRoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgSGFzaGVyID0gQ19saWIuSGFzaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gQ29uc3RhbnRzIHRhYmxlXG5cdCAgICB2YXIgVCA9IFtdO1xuXG5cdCAgICAvLyBDb21wdXRlIGNvbnN0YW50c1xuXHQgICAgKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDY0OyBpKyspIHtcblx0ICAgICAgICAgICAgVFtpXSA9IChNYXRoLmFicyhNYXRoLnNpbihpICsgMSkpICogMHgxMDAwMDAwMDApIHwgMDtcblx0ICAgICAgICB9XG5cdCAgICB9KCkpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIE1ENSBoYXNoIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIE1ENSA9IENfYWxnby5NRDUgPSBIYXNoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB0aGlzLl9oYXNoID0gbmV3IFdvcmRBcnJheS5pbml0KFtcblx0ICAgICAgICAgICAgICAgIDB4Njc0NTIzMDEsIDB4ZWZjZGFiODksXG5cdCAgICAgICAgICAgICAgICAweDk4YmFkY2ZlLCAweDEwMzI1NDc2XG5cdCAgICAgICAgICAgIF0pO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9Qcm9jZXNzQmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgLy8gU3dhcCBlbmRpYW5cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgIHZhciBvZmZzZXRfaSA9IG9mZnNldCArIGk7XG5cdCAgICAgICAgICAgICAgICB2YXIgTV9vZmZzZXRfaSA9IE1bb2Zmc2V0X2ldO1xuXG5cdCAgICAgICAgICAgICAgICBNW29mZnNldF9pXSA9IChcblx0ICAgICAgICAgICAgICAgICAgICAoKChNX29mZnNldF9pIDw8IDgpICB8IChNX29mZnNldF9pID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgICAgICgoKE1fb2Zmc2V0X2kgPDwgMjQpIHwgKE1fb2Zmc2V0X2kgPj4+IDgpKSAgJiAweGZmMDBmZjAwKVxuXHQgICAgICAgICAgICAgICAgKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgSCA9IHRoaXMuX2hhc2gud29yZHM7XG5cblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzAgID0gTVtvZmZzZXQgKyAwXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzEgID0gTVtvZmZzZXQgKyAxXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzIgID0gTVtvZmZzZXQgKyAyXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzMgID0gTVtvZmZzZXQgKyAzXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzQgID0gTVtvZmZzZXQgKyA0XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzUgID0gTVtvZmZzZXQgKyA1XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzYgID0gTVtvZmZzZXQgKyA2XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzcgID0gTVtvZmZzZXQgKyA3XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzggID0gTVtvZmZzZXQgKyA4XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzkgID0gTVtvZmZzZXQgKyA5XTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzEwID0gTVtvZmZzZXQgKyAxMF07XG5cdCAgICAgICAgICAgIHZhciBNX29mZnNldF8xMSA9IE1bb2Zmc2V0ICsgMTFdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMTIgPSBNW29mZnNldCArIDEyXTtcblx0ICAgICAgICAgICAgdmFyIE1fb2Zmc2V0XzEzID0gTVtvZmZzZXQgKyAxM107XG5cdCAgICAgICAgICAgIHZhciBNX29mZnNldF8xNCA9IE1bb2Zmc2V0ICsgMTRdO1xuXHQgICAgICAgICAgICB2YXIgTV9vZmZzZXRfMTUgPSBNW29mZnNldCArIDE1XTtcblxuXHQgICAgICAgICAgICAvLyBXb3JraW5nIHZhcmlhbGJlc1xuXHQgICAgICAgICAgICB2YXIgYSA9IEhbMF07XG5cdCAgICAgICAgICAgIHZhciBiID0gSFsxXTtcblx0ICAgICAgICAgICAgdmFyIGMgPSBIWzJdO1xuXHQgICAgICAgICAgICB2YXIgZCA9IEhbM107XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0YXRpb25cblx0ICAgICAgICAgICAgYSA9IEZGKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzAsICA3LCAgVFswXSk7XG5cdCAgICAgICAgICAgIGQgPSBGRihkLCBhLCBiLCBjLCBNX29mZnNldF8xLCAgMTIsIFRbMV0pO1xuXHQgICAgICAgICAgICBjID0gRkYoYywgZCwgYSwgYiwgTV9vZmZzZXRfMiwgIDE3LCBUWzJdKTtcblx0ICAgICAgICAgICAgYiA9IEZGKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzMsICAyMiwgVFszXSk7XG5cdCAgICAgICAgICAgIGEgPSBGRihhLCBiLCBjLCBkLCBNX29mZnNldF80LCAgNywgIFRbNF0pO1xuXHQgICAgICAgICAgICBkID0gRkYoZCwgYSwgYiwgYywgTV9vZmZzZXRfNSwgIDEyLCBUWzVdKTtcblx0ICAgICAgICAgICAgYyA9IEZGKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzYsICAxNywgVFs2XSk7XG5cdCAgICAgICAgICAgIGIgPSBGRihiLCBjLCBkLCBhLCBNX29mZnNldF83LCAgMjIsIFRbN10pO1xuXHQgICAgICAgICAgICBhID0gRkYoYSwgYiwgYywgZCwgTV9vZmZzZXRfOCwgIDcsICBUWzhdKTtcblx0ICAgICAgICAgICAgZCA9IEZGKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzksICAxMiwgVFs5XSk7XG5cdCAgICAgICAgICAgIGMgPSBGRihjLCBkLCBhLCBiLCBNX29mZnNldF8xMCwgMTcsIFRbMTBdKTtcblx0ICAgICAgICAgICAgYiA9IEZGKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzExLCAyMiwgVFsxMV0pO1xuXHQgICAgICAgICAgICBhID0gRkYoYSwgYiwgYywgZCwgTV9vZmZzZXRfMTIsIDcsICBUWzEyXSk7XG5cdCAgICAgICAgICAgIGQgPSBGRihkLCBhLCBiLCBjLCBNX29mZnNldF8xMywgMTIsIFRbMTNdKTtcblx0ICAgICAgICAgICAgYyA9IEZGKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzE0LCAxNywgVFsxNF0pO1xuXHQgICAgICAgICAgICBiID0gRkYoYiwgYywgZCwgYSwgTV9vZmZzZXRfMTUsIDIyLCBUWzE1XSk7XG5cblx0ICAgICAgICAgICAgYSA9IEdHKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzEsICA1LCAgVFsxNl0pO1xuXHQgICAgICAgICAgICBkID0gR0coZCwgYSwgYiwgYywgTV9vZmZzZXRfNiwgIDksICBUWzE3XSk7XG5cdCAgICAgICAgICAgIGMgPSBHRyhjLCBkLCBhLCBiLCBNX29mZnNldF8xMSwgMTQsIFRbMThdKTtcblx0ICAgICAgICAgICAgYiA9IEdHKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzAsICAyMCwgVFsxOV0pO1xuXHQgICAgICAgICAgICBhID0gR0coYSwgYiwgYywgZCwgTV9vZmZzZXRfNSwgIDUsICBUWzIwXSk7XG5cdCAgICAgICAgICAgIGQgPSBHRyhkLCBhLCBiLCBjLCBNX29mZnNldF8xMCwgOSwgIFRbMjFdKTtcblx0ICAgICAgICAgICAgYyA9IEdHKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzE1LCAxNCwgVFsyMl0pO1xuXHQgICAgICAgICAgICBiID0gR0coYiwgYywgZCwgYSwgTV9vZmZzZXRfNCwgIDIwLCBUWzIzXSk7XG5cdCAgICAgICAgICAgIGEgPSBHRyhhLCBiLCBjLCBkLCBNX29mZnNldF85LCAgNSwgIFRbMjRdKTtcblx0ICAgICAgICAgICAgZCA9IEdHKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzE0LCA5LCAgVFsyNV0pO1xuXHQgICAgICAgICAgICBjID0gR0coYywgZCwgYSwgYiwgTV9vZmZzZXRfMywgIDE0LCBUWzI2XSk7XG5cdCAgICAgICAgICAgIGIgPSBHRyhiLCBjLCBkLCBhLCBNX29mZnNldF84LCAgMjAsIFRbMjddKTtcblx0ICAgICAgICAgICAgYSA9IEdHKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzEzLCA1LCAgVFsyOF0pO1xuXHQgICAgICAgICAgICBkID0gR0coZCwgYSwgYiwgYywgTV9vZmZzZXRfMiwgIDksICBUWzI5XSk7XG5cdCAgICAgICAgICAgIGMgPSBHRyhjLCBkLCBhLCBiLCBNX29mZnNldF83LCAgMTQsIFRbMzBdKTtcblx0ICAgICAgICAgICAgYiA9IEdHKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzEyLCAyMCwgVFszMV0pO1xuXG5cdCAgICAgICAgICAgIGEgPSBISChhLCBiLCBjLCBkLCBNX29mZnNldF81LCAgNCwgIFRbMzJdKTtcblx0ICAgICAgICAgICAgZCA9IEhIKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzgsICAxMSwgVFszM10pO1xuXHQgICAgICAgICAgICBjID0gSEgoYywgZCwgYSwgYiwgTV9vZmZzZXRfMTEsIDE2LCBUWzM0XSk7XG5cdCAgICAgICAgICAgIGIgPSBISChiLCBjLCBkLCBhLCBNX29mZnNldF8xNCwgMjMsIFRbMzVdKTtcblx0ICAgICAgICAgICAgYSA9IEhIKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzEsICA0LCAgVFszNl0pO1xuXHQgICAgICAgICAgICBkID0gSEgoZCwgYSwgYiwgYywgTV9vZmZzZXRfNCwgIDExLCBUWzM3XSk7XG5cdCAgICAgICAgICAgIGMgPSBISChjLCBkLCBhLCBiLCBNX29mZnNldF83LCAgMTYsIFRbMzhdKTtcblx0ICAgICAgICAgICAgYiA9IEhIKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzEwLCAyMywgVFszOV0pO1xuXHQgICAgICAgICAgICBhID0gSEgoYSwgYiwgYywgZCwgTV9vZmZzZXRfMTMsIDQsICBUWzQwXSk7XG5cdCAgICAgICAgICAgIGQgPSBISChkLCBhLCBiLCBjLCBNX29mZnNldF8wLCAgMTEsIFRbNDFdKTtcblx0ICAgICAgICAgICAgYyA9IEhIKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzMsICAxNiwgVFs0Ml0pO1xuXHQgICAgICAgICAgICBiID0gSEgoYiwgYywgZCwgYSwgTV9vZmZzZXRfNiwgIDIzLCBUWzQzXSk7XG5cdCAgICAgICAgICAgIGEgPSBISChhLCBiLCBjLCBkLCBNX29mZnNldF85LCAgNCwgIFRbNDRdKTtcblx0ICAgICAgICAgICAgZCA9IEhIKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzEyLCAxMSwgVFs0NV0pO1xuXHQgICAgICAgICAgICBjID0gSEgoYywgZCwgYSwgYiwgTV9vZmZzZXRfMTUsIDE2LCBUWzQ2XSk7XG5cdCAgICAgICAgICAgIGIgPSBISChiLCBjLCBkLCBhLCBNX29mZnNldF8yLCAgMjMsIFRbNDddKTtcblxuXHQgICAgICAgICAgICBhID0gSUkoYSwgYiwgYywgZCwgTV9vZmZzZXRfMCwgIDYsICBUWzQ4XSk7XG5cdCAgICAgICAgICAgIGQgPSBJSShkLCBhLCBiLCBjLCBNX29mZnNldF83LCAgMTAsIFRbNDldKTtcblx0ICAgICAgICAgICAgYyA9IElJKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzE0LCAxNSwgVFs1MF0pO1xuXHQgICAgICAgICAgICBiID0gSUkoYiwgYywgZCwgYSwgTV9vZmZzZXRfNSwgIDIxLCBUWzUxXSk7XG5cdCAgICAgICAgICAgIGEgPSBJSShhLCBiLCBjLCBkLCBNX29mZnNldF8xMiwgNiwgIFRbNTJdKTtcblx0ICAgICAgICAgICAgZCA9IElJKGQsIGEsIGIsIGMsIE1fb2Zmc2V0XzMsICAxMCwgVFs1M10pO1xuXHQgICAgICAgICAgICBjID0gSUkoYywgZCwgYSwgYiwgTV9vZmZzZXRfMTAsIDE1LCBUWzU0XSk7XG5cdCAgICAgICAgICAgIGIgPSBJSShiLCBjLCBkLCBhLCBNX29mZnNldF8xLCAgMjEsIFRbNTVdKTtcblx0ICAgICAgICAgICAgYSA9IElJKGEsIGIsIGMsIGQsIE1fb2Zmc2V0XzgsICA2LCAgVFs1Nl0pO1xuXHQgICAgICAgICAgICBkID0gSUkoZCwgYSwgYiwgYywgTV9vZmZzZXRfMTUsIDEwLCBUWzU3XSk7XG5cdCAgICAgICAgICAgIGMgPSBJSShjLCBkLCBhLCBiLCBNX29mZnNldF82LCAgMTUsIFRbNThdKTtcblx0ICAgICAgICAgICAgYiA9IElJKGIsIGMsIGQsIGEsIE1fb2Zmc2V0XzEzLCAyMSwgVFs1OV0pO1xuXHQgICAgICAgICAgICBhID0gSUkoYSwgYiwgYywgZCwgTV9vZmZzZXRfNCwgIDYsICBUWzYwXSk7XG5cdCAgICAgICAgICAgIGQgPSBJSShkLCBhLCBiLCBjLCBNX29mZnNldF8xMSwgMTAsIFRbNjFdKTtcblx0ICAgICAgICAgICAgYyA9IElJKGMsIGQsIGEsIGIsIE1fb2Zmc2V0XzIsICAxNSwgVFs2Ml0pO1xuXHQgICAgICAgICAgICBiID0gSUkoYiwgYywgZCwgYSwgTV9vZmZzZXRfOSwgIDIxLCBUWzYzXSk7XG5cblx0ICAgICAgICAgICAgLy8gSW50ZXJtZWRpYXRlIGhhc2ggdmFsdWVcblx0ICAgICAgICAgICAgSFswXSA9IChIWzBdICsgYSkgfCAwO1xuXHQgICAgICAgICAgICBIWzFdID0gKEhbMV0gKyBiKSB8IDA7XG5cdCAgICAgICAgICAgIEhbMl0gPSAoSFsyXSArIGMpIHwgMDtcblx0ICAgICAgICAgICAgSFszXSA9IChIWzNdICsgZCkgfCAwO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9GaW5hbGl6ZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGRhdGEgPSB0aGlzLl9kYXRhO1xuXHQgICAgICAgICAgICB2YXIgZGF0YVdvcmRzID0gZGF0YS53b3JkcztcblxuXHQgICAgICAgICAgICB2YXIgbkJpdHNUb3RhbCA9IHRoaXMuX25EYXRhQnl0ZXMgKiA4O1xuXHQgICAgICAgICAgICB2YXIgbkJpdHNMZWZ0ID0gZGF0YS5zaWdCeXRlcyAqIDg7XG5cblx0ICAgICAgICAgICAgLy8gQWRkIHBhZGRpbmdcblx0ICAgICAgICAgICAgZGF0YVdvcmRzW25CaXRzTGVmdCA+Pj4gNV0gfD0gMHg4MCA8PCAoMjQgLSBuQml0c0xlZnQgJSAzMik7XG5cblx0ICAgICAgICAgICAgdmFyIG5CaXRzVG90YWxIID0gTWF0aC5mbG9vcihuQml0c1RvdGFsIC8gMHgxMDAwMDAwMDApO1xuXHQgICAgICAgICAgICB2YXIgbkJpdHNUb3RhbEwgPSBuQml0c1RvdGFsO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKCgobkJpdHNMZWZ0ICsgNjQpID4+PiA5KSA8PCA0KSArIDE1XSA9IChcblx0ICAgICAgICAgICAgICAgICgoKG5CaXRzVG90YWxIIDw8IDgpICB8IChuQml0c1RvdGFsSCA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICgoKG5CaXRzVG90YWxIIDw8IDI0KSB8IChuQml0c1RvdGFsSCA+Pj4gOCkpICAmIDB4ZmYwMGZmMDApXG5cdCAgICAgICAgICAgICk7XG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1soKChuQml0c0xlZnQgKyA2NCkgPj4+IDkpIDw8IDQpICsgMTRdID0gKFxuXHQgICAgICAgICAgICAgICAgKCgobkJpdHNUb3RhbEwgPDwgOCkgIHwgKG5CaXRzVG90YWxMID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgKCgobkJpdHNUb3RhbEwgPDwgMjQpIHwgKG5CaXRzVG90YWxMID4+PiA4KSkgICYgMHhmZjAwZmYwMClcblx0ICAgICAgICAgICAgKTtcblxuXHQgICAgICAgICAgICBkYXRhLnNpZ0J5dGVzID0gKGRhdGFXb3Jkcy5sZW5ndGggKyAxKSAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gSGFzaCBmaW5hbCBibG9ja3Ncblx0ICAgICAgICAgICAgdGhpcy5fcHJvY2VzcygpO1xuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgaGFzaCA9IHRoaXMuX2hhc2g7XG5cdCAgICAgICAgICAgIHZhciBIID0gaGFzaC53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBTd2FwIGVuZGlhblxuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDQ7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgICAgIHZhciBIX2kgPSBIW2ldO1xuXG5cdCAgICAgICAgICAgICAgICBIW2ldID0gKCgoSF9pIDw8IDgpICB8IChIX2kgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8XG5cdCAgICAgICAgICAgICAgICAgICAgICAgKCgoSF9pIDw8IDI0KSB8IChIX2kgPj4+IDgpKSAgJiAweGZmMDBmZjAwKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIFJldHVybiBmaW5hbCBjb21wdXRlZCBoYXNoXG5cdCAgICAgICAgICAgIHJldHVybiBoYXNoO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBIYXNoZXIuY2xvbmUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgY2xvbmUuX2hhc2ggPSB0aGlzLl9oYXNoLmNsb25lKCk7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGNsb25lO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICBmdW5jdGlvbiBGRihhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5cdCAgICAgICAgdmFyIG4gPSBhICsgKChiICYgYykgfCAofmIgJiBkKSkgKyB4ICsgdDtcblx0ICAgICAgICByZXR1cm4gKChuIDw8IHMpIHwgKG4gPj4+ICgzMiAtIHMpKSkgKyBiO1xuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiBHRyhhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5cdCAgICAgICAgdmFyIG4gPSBhICsgKChiICYgZCkgfCAoYyAmIH5kKSkgKyB4ICsgdDtcblx0ICAgICAgICByZXR1cm4gKChuIDw8IHMpIHwgKG4gPj4+ICgzMiAtIHMpKSkgKyBiO1xuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiBISChhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5cdCAgICAgICAgdmFyIG4gPSBhICsgKGIgXiBjIF4gZCkgKyB4ICsgdDtcblx0ICAgICAgICByZXR1cm4gKChuIDw8IHMpIHwgKG4gPj4+ICgzMiAtIHMpKSkgKyBiO1xuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiBJSShhLCBiLCBjLCBkLCB4LCBzLCB0KSB7XG5cdCAgICAgICAgdmFyIG4gPSBhICsgKGMgXiAoYiB8IH5kKSkgKyB4ICsgdDtcblx0ICAgICAgICByZXR1cm4gKChuIDw8IHMpIHwgKG4gPj4+ICgzMiAtIHMpKSkgKyBiO1xuXHQgICAgfVxuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBoYXNoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuTUQ1KCdtZXNzYWdlJyk7XG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5NRDUod29yZEFycmF5KTtcblx0ICAgICAqL1xuXHQgICAgQy5NRDUgPSBIYXNoZXIuX2NyZWF0ZUhlbHBlcihNRDUpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBITUFDJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30ga2V5IFRoZSBzZWNyZXQga2V5LlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIEhNQUMuXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBobWFjID0gQ3J5cHRvSlMuSG1hY01ENShtZXNzYWdlLCBrZXkpO1xuXHQgICAgICovXG5cdCAgICBDLkhtYWNNRDUgPSBIYXNoZXIuX2NyZWF0ZUhtYWNIZWxwZXIoTUQ1KTtcblx0fShNYXRoKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuTUQ1O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NpcGhlci1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogQ2lwaGVyIEZlZWRiYWNrIGJsb2NrIG1vZGUuXG5cdCAqL1xuXHRDcnlwdG9KUy5tb2RlLkNGQiA9IChmdW5jdGlvbiAoKSB7XG5cdCAgICB2YXIgQ0ZCID0gQ3J5cHRvSlMubGliLkJsb2NrQ2lwaGVyTW9kZS5leHRlbmQoKTtcblxuXHQgICAgQ0ZCLkVuY3J5cHRvciA9IENGQi5leHRlbmQoe1xuXHQgICAgICAgIHByb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBjaXBoZXIgPSB0aGlzLl9jaXBoZXI7XG5cdCAgICAgICAgICAgIHZhciBibG9ja1NpemUgPSBjaXBoZXIuYmxvY2tTaXplO1xuXG5cdCAgICAgICAgICAgIGdlbmVyYXRlS2V5c3RyZWFtQW5kRW5jcnlwdC5jYWxsKHRoaXMsIHdvcmRzLCBvZmZzZXQsIGJsb2NrU2l6ZSwgY2lwaGVyKTtcblxuXHQgICAgICAgICAgICAvLyBSZW1lbWJlciB0aGlzIGJsb2NrIHRvIHVzZSB3aXRoIG5leHQgYmxvY2tcblx0ICAgICAgICAgICAgdGhpcy5fcHJldkJsb2NrID0gd29yZHMuc2xpY2Uob2Zmc2V0LCBvZmZzZXQgKyBibG9ja1NpemUpO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICBDRkIuRGVjcnlwdG9yID0gQ0ZCLmV4dGVuZCh7XG5cdCAgICAgICAgcHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAod29yZHMsIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGNpcGhlciA9IHRoaXMuX2NpcGhlcjtcblx0ICAgICAgICAgICAgdmFyIGJsb2NrU2l6ZSA9IGNpcGhlci5ibG9ja1NpemU7XG5cblx0ICAgICAgICAgICAgLy8gUmVtZW1iZXIgdGhpcyBibG9jayB0byB1c2Ugd2l0aCBuZXh0IGJsb2NrXG5cdCAgICAgICAgICAgIHZhciB0aGlzQmxvY2sgPSB3b3Jkcy5zbGljZShvZmZzZXQsIG9mZnNldCArIGJsb2NrU2l6ZSk7XG5cblx0ICAgICAgICAgICAgZ2VuZXJhdGVLZXlzdHJlYW1BbmRFbmNyeXB0LmNhbGwodGhpcywgd29yZHMsIG9mZnNldCwgYmxvY2tTaXplLCBjaXBoZXIpO1xuXG5cdCAgICAgICAgICAgIC8vIFRoaXMgYmxvY2sgYmVjb21lcyB0aGUgcHJldmlvdXMgYmxvY2tcblx0ICAgICAgICAgICAgdGhpcy5fcHJldkJsb2NrID0gdGhpc0Jsb2NrO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICBmdW5jdGlvbiBnZW5lcmF0ZUtleXN0cmVhbUFuZEVuY3J5cHQod29yZHMsIG9mZnNldCwgYmxvY2tTaXplLCBjaXBoZXIpIHtcblx0ICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgIHZhciBpdiA9IHRoaXMuX2l2O1xuXG5cdCAgICAgICAgLy8gR2VuZXJhdGUga2V5c3RyZWFtXG5cdCAgICAgICAgaWYgKGl2KSB7XG5cdCAgICAgICAgICAgIHZhciBrZXlzdHJlYW0gPSBpdi5zbGljZSgwKTtcblxuXHQgICAgICAgICAgICAvLyBSZW1vdmUgSVYgZm9yIHN1YnNlcXVlbnQgYmxvY2tzXG5cdCAgICAgICAgICAgIHRoaXMuX2l2ID0gdW5kZWZpbmVkO1xuXHQgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgIHZhciBrZXlzdHJlYW0gPSB0aGlzLl9wcmV2QmxvY2s7XG5cdCAgICAgICAgfVxuXHQgICAgICAgIGNpcGhlci5lbmNyeXB0QmxvY2soa2V5c3RyZWFtLCAwKTtcblxuXHQgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJsb2NrU2l6ZTsgaSsrKSB7XG5cdCAgICAgICAgICAgIHdvcmRzW29mZnNldCArIGldIF49IGtleXN0cmVhbVtpXTtcblx0ICAgICAgICB9XG5cdCAgICB9XG5cblx0ICAgIHJldHVybiBDRkI7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMubW9kZS5DRkI7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdC8qKiBAcHJlc2VydmVcblx0ICogQ291bnRlciBibG9jayBtb2RlIGNvbXBhdGlibGUgd2l0aCAgRHIgQnJpYW4gR2xhZG1hbiBmaWxlZW5jLmNcblx0ICogZGVyaXZlZCBmcm9tIENyeXB0b0pTLm1vZGUuQ1RSXG5cdCAqIEphbiBIcnVieSBqaHJ1Ynkud2ViQGdtYWlsLmNvbVxuXHQgKi9cblx0Q3J5cHRvSlMubW9kZS5DVFJHbGFkbWFuID0gKGZ1bmN0aW9uICgpIHtcblx0ICAgIHZhciBDVFJHbGFkbWFuID0gQ3J5cHRvSlMubGliLkJsb2NrQ2lwaGVyTW9kZS5leHRlbmQoKTtcblxuXHRcdGZ1bmN0aW9uIGluY1dvcmQod29yZClcblx0XHR7XG5cdFx0XHRpZiAoKCh3b3JkID4+IDI0KSAmIDB4ZmYpID09PSAweGZmKSB7IC8vb3ZlcmZsb3dcblx0XHRcdHZhciBiMSA9ICh3b3JkID4+IDE2KSYweGZmO1xuXHRcdFx0dmFyIGIyID0gKHdvcmQgPj4gOCkmMHhmZjtcblx0XHRcdHZhciBiMyA9IHdvcmQgJiAweGZmO1xuXG5cdFx0XHRpZiAoYjEgPT09IDB4ZmYpIC8vIG92ZXJmbG93IGIxXG5cdFx0XHR7XG5cdFx0XHRiMSA9IDA7XG5cdFx0XHRpZiAoYjIgPT09IDB4ZmYpXG5cdFx0XHR7XG5cdFx0XHRcdGIyID0gMDtcblx0XHRcdFx0aWYgKGIzID09PSAweGZmKVxuXHRcdFx0XHR7XG5cdFx0XHRcdFx0YjMgPSAwO1xuXHRcdFx0XHR9XG5cdFx0XHRcdGVsc2Vcblx0XHRcdFx0e1xuXHRcdFx0XHRcdCsrYjM7XG5cdFx0XHRcdH1cblx0XHRcdH1cblx0XHRcdGVsc2Vcblx0XHRcdHtcblx0XHRcdFx0KytiMjtcblx0XHRcdH1cblx0XHRcdH1cblx0XHRcdGVsc2Vcblx0XHRcdHtcblx0XHRcdCsrYjE7XG5cdFx0XHR9XG5cblx0XHRcdHdvcmQgPSAwO1xuXHRcdFx0d29yZCArPSAoYjEgPDwgMTYpO1xuXHRcdFx0d29yZCArPSAoYjIgPDwgOCk7XG5cdFx0XHR3b3JkICs9IGIzO1xuXHRcdFx0fVxuXHRcdFx0ZWxzZVxuXHRcdFx0e1xuXHRcdFx0d29yZCArPSAoMHgwMSA8PCAyNCk7XG5cdFx0XHR9XG5cdFx0XHRyZXR1cm4gd29yZDtcblx0XHR9XG5cblx0XHRmdW5jdGlvbiBpbmNDb3VudGVyKGNvdW50ZXIpXG5cdFx0e1xuXHRcdFx0aWYgKChjb3VudGVyWzBdID0gaW5jV29yZChjb3VudGVyWzBdKSkgPT09IDApXG5cdFx0XHR7XG5cdFx0XHRcdC8vIGVuY3JfZGF0YSBpbiBmaWxlZW5jLmMgZnJvbSAgRHIgQnJpYW4gR2xhZG1hbidzIGNvdW50cyBvbmx5IHdpdGggRFdPUkQgaiA8IDhcblx0XHRcdFx0Y291bnRlclsxXSA9IGluY1dvcmQoY291bnRlclsxXSk7XG5cdFx0XHR9XG5cdFx0XHRyZXR1cm4gY291bnRlcjtcblx0XHR9XG5cblx0ICAgIHZhciBFbmNyeXB0b3IgPSBDVFJHbGFkbWFuLkVuY3J5cHRvciA9IENUUkdsYWRtYW4uZXh0ZW5kKHtcblx0ICAgICAgICBwcm9jZXNzQmxvY2s6IGZ1bmN0aW9uICh3b3Jkcywgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgY2lwaGVyID0gdGhpcy5fY2lwaGVyXG5cdCAgICAgICAgICAgIHZhciBibG9ja1NpemUgPSBjaXBoZXIuYmxvY2tTaXplO1xuXHQgICAgICAgICAgICB2YXIgaXYgPSB0aGlzLl9pdjtcblx0ICAgICAgICAgICAgdmFyIGNvdW50ZXIgPSB0aGlzLl9jb3VudGVyO1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGtleXN0cmVhbVxuXHQgICAgICAgICAgICBpZiAoaXYpIHtcblx0ICAgICAgICAgICAgICAgIGNvdW50ZXIgPSB0aGlzLl9jb3VudGVyID0gaXYuc2xpY2UoMCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFJlbW92ZSBJViBmb3Igc3Vic2VxdWVudCBibG9ja3Ncblx0ICAgICAgICAgICAgICAgIHRoaXMuX2l2ID0gdW5kZWZpbmVkO1xuXHQgICAgICAgICAgICB9XG5cblx0XHRcdFx0aW5jQ291bnRlcihjb3VudGVyKTtcblxuXHRcdFx0XHR2YXIga2V5c3RyZWFtID0gY291bnRlci5zbGljZSgwKTtcblx0ICAgICAgICAgICAgY2lwaGVyLmVuY3J5cHRCbG9jayhrZXlzdHJlYW0sIDApO1xuXG5cdCAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBibG9ja1NpemU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbb2Zmc2V0ICsgaV0gXj0ga2V5c3RyZWFtW2ldO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIENUUkdsYWRtYW4uRGVjcnlwdG9yID0gRW5jcnlwdG9yO1xuXG5cdCAgICByZXR1cm4gQ1RSR2xhZG1hbjtcblx0fSgpKTtcblxuXG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMubW9kZS5DVFJHbGFkbWFuO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NpcGhlci1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogQ291bnRlciBibG9jayBtb2RlLlxuXHQgKi9cblx0Q3J5cHRvSlMubW9kZS5DVFIgPSAoZnVuY3Rpb24gKCkge1xuXHQgICAgdmFyIENUUiA9IENyeXB0b0pTLmxpYi5CbG9ja0NpcGhlck1vZGUuZXh0ZW5kKCk7XG5cblx0ICAgIHZhciBFbmNyeXB0b3IgPSBDVFIuRW5jcnlwdG9yID0gQ1RSLmV4dGVuZCh7XG5cdCAgICAgICAgcHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAod29yZHMsIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGNpcGhlciA9IHRoaXMuX2NpcGhlclxuXHQgICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gY2lwaGVyLmJsb2NrU2l6ZTtcblx0ICAgICAgICAgICAgdmFyIGl2ID0gdGhpcy5faXY7XG5cdCAgICAgICAgICAgIHZhciBjb3VudGVyID0gdGhpcy5fY291bnRlcjtcblxuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSBrZXlzdHJlYW1cblx0ICAgICAgICAgICAgaWYgKGl2KSB7XG5cdCAgICAgICAgICAgICAgICBjb3VudGVyID0gdGhpcy5fY291bnRlciA9IGl2LnNsaWNlKDApO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBSZW1vdmUgSVYgZm9yIHN1YnNlcXVlbnQgYmxvY2tzXG5cdCAgICAgICAgICAgICAgICB0aGlzLl9pdiA9IHVuZGVmaW5lZDtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICB2YXIga2V5c3RyZWFtID0gY291bnRlci5zbGljZSgwKTtcblx0ICAgICAgICAgICAgY2lwaGVyLmVuY3J5cHRCbG9jayhrZXlzdHJlYW0sIDApO1xuXG5cdCAgICAgICAgICAgIC8vIEluY3JlbWVudCBjb3VudGVyXG5cdCAgICAgICAgICAgIGNvdW50ZXJbYmxvY2tTaXplIC0gMV0gPSAoY291bnRlcltibG9ja1NpemUgLSAxXSArIDEpIHwgMFxuXG5cdCAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBibG9ja1NpemU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbb2Zmc2V0ICsgaV0gXj0ga2V5c3RyZWFtW2ldO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIENUUi5EZWNyeXB0b3IgPSBFbmNyeXB0b3I7XG5cblx0ICAgIHJldHVybiBDVFI7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMubW9kZS5DVFI7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdC8qKlxuXHQgKiBFbGVjdHJvbmljIENvZGVib29rIGJsb2NrIG1vZGUuXG5cdCAqL1xuXHRDcnlwdG9KUy5tb2RlLkVDQiA9IChmdW5jdGlvbiAoKSB7XG5cdCAgICB2YXIgRUNCID0gQ3J5cHRvSlMubGliLkJsb2NrQ2lwaGVyTW9kZS5leHRlbmQoKTtcblxuXHQgICAgRUNCLkVuY3J5cHRvciA9IEVDQi5leHRlbmQoe1xuXHQgICAgICAgIHByb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgdGhpcy5fY2lwaGVyLmVuY3J5cHRCbG9jayh3b3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgRUNCLkRlY3J5cHRvciA9IEVDQi5leHRlbmQoe1xuXHQgICAgICAgIHByb2Nlc3NCbG9jazogZnVuY3Rpb24gKHdvcmRzLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgdGhpcy5fY2lwaGVyLmRlY3J5cHRCbG9jayh3b3Jkcywgb2Zmc2V0KTtcblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgcmV0dXJuIEVDQjtcblx0fSgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5tb2RlLkVDQjtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9jaXBoZXItY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9jaXBoZXItY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0LyoqXG5cdCAqIE91dHB1dCBGZWVkYmFjayBibG9jayBtb2RlLlxuXHQgKi9cblx0Q3J5cHRvSlMubW9kZS5PRkIgPSAoZnVuY3Rpb24gKCkge1xuXHQgICAgdmFyIE9GQiA9IENyeXB0b0pTLmxpYi5CbG9ja0NpcGhlck1vZGUuZXh0ZW5kKCk7XG5cblx0ICAgIHZhciBFbmNyeXB0b3IgPSBPRkIuRW5jcnlwdG9yID0gT0ZCLmV4dGVuZCh7XG5cdCAgICAgICAgcHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAod29yZHMsIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGNpcGhlciA9IHRoaXMuX2NpcGhlclxuXHQgICAgICAgICAgICB2YXIgYmxvY2tTaXplID0gY2lwaGVyLmJsb2NrU2l6ZTtcblx0ICAgICAgICAgICAgdmFyIGl2ID0gdGhpcy5faXY7XG5cdCAgICAgICAgICAgIHZhciBrZXlzdHJlYW0gPSB0aGlzLl9rZXlzdHJlYW07XG5cblx0ICAgICAgICAgICAgLy8gR2VuZXJhdGUga2V5c3RyZWFtXG5cdCAgICAgICAgICAgIGlmIChpdikge1xuXHQgICAgICAgICAgICAgICAga2V5c3RyZWFtID0gdGhpcy5fa2V5c3RyZWFtID0gaXYuc2xpY2UoMCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFJlbW92ZSBJViBmb3Igc3Vic2VxdWVudCBibG9ja3Ncblx0ICAgICAgICAgICAgICAgIHRoaXMuX2l2ID0gdW5kZWZpbmVkO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIGNpcGhlci5lbmNyeXB0QmxvY2soa2V5c3RyZWFtLCAwKTtcblxuXHQgICAgICAgICAgICAvLyBFbmNyeXB0XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYmxvY2tTaXplOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHdvcmRzW29mZnNldCArIGldIF49IGtleXN0cmVhbVtpXTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICBPRkIuRGVjcnlwdG9yID0gRW5jcnlwdG9yO1xuXG5cdCAgICByZXR1cm4gT0ZCO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLm1vZGUuT0ZCO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NpcGhlci1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogQU5TSSBYLjkyMyBwYWRkaW5nIHN0cmF0ZWd5LlxuXHQgKi9cblx0Q3J5cHRvSlMucGFkLkFuc2lYOTIzID0ge1xuXHQgICAgcGFkOiBmdW5jdGlvbiAoZGF0YSwgYmxvY2tTaXplKSB7XG5cdCAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgdmFyIGRhdGFTaWdCeXRlcyA9IGRhdGEuc2lnQnl0ZXM7XG5cdCAgICAgICAgdmFyIGJsb2NrU2l6ZUJ5dGVzID0gYmxvY2tTaXplICogNDtcblxuXHQgICAgICAgIC8vIENvdW50IHBhZGRpbmcgYnl0ZXNcblx0ICAgICAgICB2YXIgblBhZGRpbmdCeXRlcyA9IGJsb2NrU2l6ZUJ5dGVzIC0gZGF0YVNpZ0J5dGVzICUgYmxvY2tTaXplQnl0ZXM7XG5cblx0ICAgICAgICAvLyBDb21wdXRlIGxhc3QgYnl0ZSBwb3NpdGlvblxuXHQgICAgICAgIHZhciBsYXN0Qnl0ZVBvcyA9IGRhdGFTaWdCeXRlcyArIG5QYWRkaW5nQnl0ZXMgLSAxO1xuXG5cdCAgICAgICAgLy8gUGFkXG5cdCAgICAgICAgZGF0YS5jbGFtcCgpO1xuXHQgICAgICAgIGRhdGEud29yZHNbbGFzdEJ5dGVQb3MgPj4+IDJdIHw9IG5QYWRkaW5nQnl0ZXMgPDwgKDI0IC0gKGxhc3RCeXRlUG9zICUgNCkgKiA4KTtcblx0ICAgICAgICBkYXRhLnNpZ0J5dGVzICs9IG5QYWRkaW5nQnl0ZXM7XG5cdCAgICB9LFxuXG5cdCAgICB1bnBhZDogZnVuY3Rpb24gKGRhdGEpIHtcblx0ICAgICAgICAvLyBHZXQgbnVtYmVyIG9mIHBhZGRpbmcgYnl0ZXMgZnJvbSBsYXN0IGJ5dGVcblx0ICAgICAgICB2YXIgblBhZGRpbmdCeXRlcyA9IGRhdGEud29yZHNbKGRhdGEuc2lnQnl0ZXMgLSAxKSA+Pj4gMl0gJiAweGZmO1xuXG5cdCAgICAgICAgLy8gUmVtb3ZlIHBhZGRpbmdcblx0ICAgICAgICBkYXRhLnNpZ0J5dGVzIC09IG5QYWRkaW5nQnl0ZXM7XG5cdCAgICB9XG5cdH07XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMucGFkLkFuc2l4OTIzO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NpcGhlci1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogSVNPIDEwMTI2IHBhZGRpbmcgc3RyYXRlZ3kuXG5cdCAqL1xuXHRDcnlwdG9KUy5wYWQuSXNvMTAxMjYgPSB7XG5cdCAgICBwYWQ6IGZ1bmN0aW9uIChkYXRhLCBibG9ja1NpemUpIHtcblx0ICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgIHZhciBibG9ja1NpemVCeXRlcyA9IGJsb2NrU2l6ZSAqIDQ7XG5cblx0ICAgICAgICAvLyBDb3VudCBwYWRkaW5nIGJ5dGVzXG5cdCAgICAgICAgdmFyIG5QYWRkaW5nQnl0ZXMgPSBibG9ja1NpemVCeXRlcyAtIGRhdGEuc2lnQnl0ZXMgJSBibG9ja1NpemVCeXRlcztcblxuXHQgICAgICAgIC8vIFBhZFxuXHQgICAgICAgIGRhdGEuY29uY2F0KENyeXB0b0pTLmxpYi5Xb3JkQXJyYXkucmFuZG9tKG5QYWRkaW5nQnl0ZXMgLSAxKSkuXG5cdCAgICAgICAgICAgICBjb25jYXQoQ3J5cHRvSlMubGliLldvcmRBcnJheS5jcmVhdGUoW25QYWRkaW5nQnl0ZXMgPDwgMjRdLCAxKSk7XG5cdCAgICB9LFxuXG5cdCAgICB1bnBhZDogZnVuY3Rpb24gKGRhdGEpIHtcblx0ICAgICAgICAvLyBHZXQgbnVtYmVyIG9mIHBhZGRpbmcgYnl0ZXMgZnJvbSBsYXN0IGJ5dGVcblx0ICAgICAgICB2YXIgblBhZGRpbmdCeXRlcyA9IGRhdGEud29yZHNbKGRhdGEuc2lnQnl0ZXMgLSAxKSA+Pj4gMl0gJiAweGZmO1xuXG5cdCAgICAgICAgLy8gUmVtb3ZlIHBhZGRpbmdcblx0ICAgICAgICBkYXRhLnNpZ0J5dGVzIC09IG5QYWRkaW5nQnl0ZXM7XG5cdCAgICB9XG5cdH07XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMucGFkLklzbzEwMTI2O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NpcGhlci1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogSVNPL0lFQyA5Nzk3LTEgUGFkZGluZyBNZXRob2QgMi5cblx0ICovXG5cdENyeXB0b0pTLnBhZC5Jc285Nzk3MSA9IHtcblx0ICAgIHBhZDogZnVuY3Rpb24gKGRhdGEsIGJsb2NrU2l6ZSkge1xuXHQgICAgICAgIC8vIEFkZCAweDgwIGJ5dGVcblx0ICAgICAgICBkYXRhLmNvbmNhdChDcnlwdG9KUy5saWIuV29yZEFycmF5LmNyZWF0ZShbMHg4MDAwMDAwMF0sIDEpKTtcblxuXHQgICAgICAgIC8vIFplcm8gcGFkIHRoZSByZXN0XG5cdCAgICAgICAgQ3J5cHRvSlMucGFkLlplcm9QYWRkaW5nLnBhZChkYXRhLCBibG9ja1NpemUpO1xuXHQgICAgfSxcblxuXHQgICAgdW5wYWQ6IGZ1bmN0aW9uIChkYXRhKSB7XG5cdCAgICAgICAgLy8gUmVtb3ZlIHplcm8gcGFkZGluZ1xuXHQgICAgICAgIENyeXB0b0pTLnBhZC5aZXJvUGFkZGluZy51bnBhZChkYXRhKTtcblxuXHQgICAgICAgIC8vIFJlbW92ZSBvbmUgbW9yZSBieXRlIC0tIHRoZSAweDgwIGJ5dGVcblx0ICAgICAgICBkYXRhLnNpZ0J5dGVzLS07XG5cdCAgICB9XG5cdH07XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMucGFkLklzbzk3OTcxO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL2NpcGhlci1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQvKipcblx0ICogQSBub29wIHBhZGRpbmcgc3RyYXRlZ3kuXG5cdCAqL1xuXHRDcnlwdG9KUy5wYWQuTm9QYWRkaW5nID0ge1xuXHQgICAgcGFkOiBmdW5jdGlvbiAoKSB7XG5cdCAgICB9LFxuXG5cdCAgICB1bnBhZDogZnVuY3Rpb24gKCkge1xuXHQgICAgfVxuXHR9O1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLnBhZC5Ob1BhZGRpbmc7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vY2lwaGVyLWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdC8qKlxuXHQgKiBaZXJvIHBhZGRpbmcgc3RyYXRlZ3kuXG5cdCAqL1xuXHRDcnlwdG9KUy5wYWQuWmVyb1BhZGRpbmcgPSB7XG5cdCAgICBwYWQ6IGZ1bmN0aW9uIChkYXRhLCBibG9ja1NpemUpIHtcblx0ICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgIHZhciBibG9ja1NpemVCeXRlcyA9IGJsb2NrU2l6ZSAqIDQ7XG5cblx0ICAgICAgICAvLyBQYWRcblx0ICAgICAgICBkYXRhLmNsYW1wKCk7XG5cdCAgICAgICAgZGF0YS5zaWdCeXRlcyArPSBibG9ja1NpemVCeXRlcyAtICgoZGF0YS5zaWdCeXRlcyAlIGJsb2NrU2l6ZUJ5dGVzKSB8fCBibG9ja1NpemVCeXRlcyk7XG5cdCAgICB9LFxuXG5cdCAgICB1bnBhZDogZnVuY3Rpb24gKGRhdGEpIHtcblx0ICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgIHZhciBkYXRhV29yZHMgPSBkYXRhLndvcmRzO1xuXG5cdCAgICAgICAgLy8gVW5wYWRcblx0ICAgICAgICB2YXIgaSA9IGRhdGEuc2lnQnl0ZXMgLSAxO1xuXHQgICAgICAgIHdoaWxlICghKChkYXRhV29yZHNbaSA+Pj4gMl0gPj4+ICgyNCAtIChpICUgNCkgKiA4KSkgJiAweGZmKSkge1xuXHQgICAgICAgICAgICBpLS07XG5cdCAgICAgICAgfVxuXHQgICAgICAgIGRhdGEuc2lnQnl0ZXMgPSBpICsgMTtcblx0ICAgIH1cblx0fTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5wYWQuWmVyb1BhZGRpbmc7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4vc2hhMVwiKSwgcmVxdWlyZShcIi4vaG1hY1wiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCIsIFwiLi9zaGExXCIsIFwiLi9obWFjXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgQmFzZSA9IENfbGliLkJhc2U7XG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5O1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblx0ICAgIHZhciBTSEExID0gQ19hbGdvLlNIQTE7XG5cdCAgICB2YXIgSE1BQyA9IENfYWxnby5ITUFDO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFBhc3N3b3JkLUJhc2VkIEtleSBEZXJpdmF0aW9uIEZ1bmN0aW9uIDIgYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgUEJLREYyID0gQ19hbGdvLlBCS0RGMiA9IEJhc2UuZXh0ZW5kKHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb25maWd1cmF0aW9uIG9wdGlvbnMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcHJvcGVydHkge251bWJlcn0ga2V5U2l6ZSBUaGUga2V5IHNpemUgaW4gd29yZHMgdG8gZ2VuZXJhdGUuIERlZmF1bHQ6IDQgKDEyOCBiaXRzKVxuXHQgICAgICAgICAqIEBwcm9wZXJ0eSB7SGFzaGVyfSBoYXNoZXIgVGhlIGhhc2hlciB0byB1c2UuIERlZmF1bHQ6IFNIQTFcblx0ICAgICAgICAgKiBAcHJvcGVydHkge251bWJlcn0gaXRlcmF0aW9ucyBUaGUgbnVtYmVyIG9mIGl0ZXJhdGlvbnMgdG8gcGVyZm9ybS4gRGVmYXVsdDogMVxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNmZzogQmFzZS5leHRlbmQoe1xuXHQgICAgICAgICAgICBrZXlTaXplOiAxMjgvMzIsXG5cdCAgICAgICAgICAgIGhhc2hlcjogU0hBMSxcblx0ICAgICAgICAgICAgaXRlcmF0aW9uczogMVxuXHQgICAgICAgIH0pLFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogSW5pdGlhbGl6ZXMgYSBuZXdseSBjcmVhdGVkIGtleSBkZXJpdmF0aW9uIGZ1bmN0aW9uLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtPYmplY3R9IGNmZyAoT3B0aW9uYWwpIFRoZSBjb25maWd1cmF0aW9uIG9wdGlvbnMgdG8gdXNlIGZvciB0aGUgZGVyaXZhdGlvbi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGtkZiA9IENyeXB0b0pTLmFsZ28uUEJLREYyLmNyZWF0ZSgpO1xuXHQgICAgICAgICAqICAgICB2YXIga2RmID0gQ3J5cHRvSlMuYWxnby5QQktERjIuY3JlYXRlKHsga2V5U2l6ZTogOCB9KTtcblx0ICAgICAgICAgKiAgICAgdmFyIGtkZiA9IENyeXB0b0pTLmFsZ28uUEJLREYyLmNyZWF0ZSh7IGtleVNpemU6IDgsIGl0ZXJhdGlvbnM6IDEwMDAgfSk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKGNmZykge1xuXHQgICAgICAgICAgICB0aGlzLmNmZyA9IHRoaXMuY2ZnLmV4dGVuZChjZmcpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb21wdXRlcyB0aGUgUGFzc3dvcmQtQmFzZWQgS2V5IERlcml2YXRpb24gRnVuY3Rpb24gMi5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gcGFzc3dvcmQgVGhlIHBhc3N3b3JkLlxuXHQgICAgICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gc2FsdCBBIHNhbHQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBkZXJpdmVkIGtleS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGtleSA9IGtkZi5jb21wdXRlKHBhc3N3b3JkLCBzYWx0KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICBjb21wdXRlOiBmdW5jdGlvbiAocGFzc3dvcmQsIHNhbHQpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIGNmZyA9IHRoaXMuY2ZnO1xuXG5cdCAgICAgICAgICAgIC8vIEluaXQgSE1BQ1xuXHQgICAgICAgICAgICB2YXIgaG1hYyA9IEhNQUMuY3JlYXRlKGNmZy5oYXNoZXIsIHBhc3N3b3JkKTtcblxuXHQgICAgICAgICAgICAvLyBJbml0aWFsIHZhbHVlc1xuXHQgICAgICAgICAgICB2YXIgZGVyaXZlZEtleSA9IFdvcmRBcnJheS5jcmVhdGUoKTtcblx0ICAgICAgICAgICAgdmFyIGJsb2NrSW5kZXggPSBXb3JkQXJyYXkuY3JlYXRlKFsweDAwMDAwMDAxXSk7XG5cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkZXJpdmVkS2V5V29yZHMgPSBkZXJpdmVkS2V5LndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgYmxvY2tJbmRleFdvcmRzID0gYmxvY2tJbmRleC53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIGtleVNpemUgPSBjZmcua2V5U2l6ZTtcblx0ICAgICAgICAgICAgdmFyIGl0ZXJhdGlvbnMgPSBjZmcuaXRlcmF0aW9ucztcblxuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSBrZXlcblx0ICAgICAgICAgICAgd2hpbGUgKGRlcml2ZWRLZXlXb3Jkcy5sZW5ndGggPCBrZXlTaXplKSB7XG5cdCAgICAgICAgICAgICAgICB2YXIgYmxvY2sgPSBobWFjLnVwZGF0ZShzYWx0KS5maW5hbGl6ZShibG9ja0luZGV4KTtcblx0ICAgICAgICAgICAgICAgIGhtYWMucmVzZXQoKTtcblxuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgICAgICB2YXIgYmxvY2tXb3JkcyA9IGJsb2NrLndvcmRzO1xuXHQgICAgICAgICAgICAgICAgdmFyIGJsb2NrV29yZHNMZW5ndGggPSBibG9ja1dvcmRzLmxlbmd0aDtcblxuXHQgICAgICAgICAgICAgICAgLy8gSXRlcmF0aW9uc1xuXHQgICAgICAgICAgICAgICAgdmFyIGludGVybWVkaWF0ZSA9IGJsb2NrO1xuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDE7IGkgPCBpdGVyYXRpb25zOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgICAgICBpbnRlcm1lZGlhdGUgPSBobWFjLmZpbmFsaXplKGludGVybWVkaWF0ZSk7XG5cdCAgICAgICAgICAgICAgICAgICAgaG1hYy5yZXNldCgpO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgaW50ZXJtZWRpYXRlV29yZHMgPSBpbnRlcm1lZGlhdGUud29yZHM7XG5cblx0ICAgICAgICAgICAgICAgICAgICAvLyBYT1IgaW50ZXJtZWRpYXRlIHdpdGggYmxvY2tcblx0ICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IGJsb2NrV29yZHNMZW5ndGg7IGorKykge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICBibG9ja1dvcmRzW2pdIF49IGludGVybWVkaWF0ZVdvcmRzW2pdO1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgZGVyaXZlZEtleS5jb25jYXQoYmxvY2spO1xuXHQgICAgICAgICAgICAgICAgYmxvY2tJbmRleFdvcmRzWzBdKys7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgZGVyaXZlZEtleS5zaWdCeXRlcyA9IGtleVNpemUgKiA0O1xuXG5cdCAgICAgICAgICAgIHJldHVybiBkZXJpdmVkS2V5O1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIENvbXB1dGVzIHRoZSBQYXNzd29yZC1CYXNlZCBLZXkgRGVyaXZhdGlvbiBGdW5jdGlvbiAyLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gcGFzc3dvcmQgVGhlIHBhc3N3b3JkLlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBzYWx0IEEgc2FsdC5cblx0ICAgICAqIEBwYXJhbSB7T2JqZWN0fSBjZmcgKE9wdGlvbmFsKSBUaGUgY29uZmlndXJhdGlvbiBvcHRpb25zIHRvIHVzZSBmb3IgdGhpcyBjb21wdXRhdGlvbi5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBkZXJpdmVkIGtleS5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGtleSA9IENyeXB0b0pTLlBCS0RGMihwYXNzd29yZCwgc2FsdCk7XG5cdCAgICAgKiAgICAgdmFyIGtleSA9IENyeXB0b0pTLlBCS0RGMihwYXNzd29yZCwgc2FsdCwgeyBrZXlTaXplOiA4IH0pO1xuXHQgICAgICogICAgIHZhciBrZXkgPSBDcnlwdG9KUy5QQktERjIocGFzc3dvcmQsIHNhbHQsIHsga2V5U2l6ZTogOCwgaXRlcmF0aW9uczogMTAwMCB9KTtcblx0ICAgICAqL1xuXHQgICAgQy5QQktERjIgPSBmdW5jdGlvbiAocGFzc3dvcmQsIHNhbHQsIGNmZykge1xuXHQgICAgICAgIHJldHVybiBQQktERjIuY3JlYXRlKGNmZykuY29tcHV0ZShwYXNzd29yZCwgc2FsdCk7XG5cdCAgICB9O1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLlBCS0RGMjtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9lbmMtYmFzZTY0XCIpLCByZXF1aXJlKFwiLi9tZDVcIiksIHJlcXVpcmUoXCIuL2V2cGtkZlwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vZW5jLWJhc2U2NFwiLCBcIi4vbWQ1XCIsIFwiLi9ldnBrZGZcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgU3RyZWFtQ2lwaGVyID0gQ19saWIuU3RyZWFtQ2lwaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gUmV1c2FibGUgb2JqZWN0c1xuXHQgICAgdmFyIFMgID0gW107XG5cdCAgICB2YXIgQ18gPSBbXTtcblx0ICAgIHZhciBHICA9IFtdO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFJhYmJpdCBzdHJlYW0gY2lwaGVyIGFsZ29yaXRobS5cblx0ICAgICAqXG5cdCAgICAgKiBUaGlzIGlzIGEgbGVnYWN5IHZlcnNpb24gdGhhdCBuZWdsZWN0ZWQgdG8gY29udmVydCB0aGUga2V5IHRvIGxpdHRsZS1lbmRpYW4uXG5cdCAgICAgKiBUaGlzIGVycm9yIGRvZXNuJ3QgYWZmZWN0IHRoZSBjaXBoZXIncyBzZWN1cml0eSxcblx0ICAgICAqIGJ1dCBpdCBkb2VzIGFmZmVjdCBpdHMgY29tcGF0aWJpbGl0eSB3aXRoIG90aGVyIGltcGxlbWVudGF0aW9ucy5cblx0ICAgICAqL1xuXHQgICAgdmFyIFJhYmJpdExlZ2FjeSA9IENfYWxnby5SYWJiaXRMZWdhY3kgPSBTdHJlYW1DaXBoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIEsgPSB0aGlzLl9rZXkud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBpdiA9IHRoaXMuY2ZnLml2O1xuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGluaXRpYWwgc3RhdGUgdmFsdWVzXG5cdCAgICAgICAgICAgIHZhciBYID0gdGhpcy5fWCA9IFtcblx0ICAgICAgICAgICAgICAgIEtbMF0sIChLWzNdIDw8IDE2KSB8IChLWzJdID4+PiAxNiksXG5cdCAgICAgICAgICAgICAgICBLWzFdLCAoS1swXSA8PCAxNikgfCAoS1szXSA+Pj4gMTYpLFxuXHQgICAgICAgICAgICAgICAgS1syXSwgKEtbMV0gPDwgMTYpIHwgKEtbMF0gPj4+IDE2KSxcblx0ICAgICAgICAgICAgICAgIEtbM10sIChLWzJdIDw8IDE2KSB8IChLWzFdID4+PiAxNilcblx0ICAgICAgICAgICAgXTtcblxuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSBpbml0aWFsIGNvdW50ZXIgdmFsdWVzXG5cdCAgICAgICAgICAgIHZhciBDID0gdGhpcy5fQyA9IFtcblx0ICAgICAgICAgICAgICAgIChLWzJdIDw8IDE2KSB8IChLWzJdID4+PiAxNiksIChLWzBdICYgMHhmZmZmMDAwMCkgfCAoS1sxXSAmIDB4MDAwMGZmZmYpLFxuXHQgICAgICAgICAgICAgICAgKEtbM10gPDwgMTYpIHwgKEtbM10gPj4+IDE2KSwgKEtbMV0gJiAweGZmZmYwMDAwKSB8IChLWzJdICYgMHgwMDAwZmZmZiksXG5cdCAgICAgICAgICAgICAgICAoS1swXSA8PCAxNikgfCAoS1swXSA+Pj4gMTYpLCAoS1syXSAmIDB4ZmZmZjAwMDApIHwgKEtbM10gJiAweDAwMDBmZmZmKSxcblx0ICAgICAgICAgICAgICAgIChLWzFdIDw8IDE2KSB8IChLWzFdID4+PiAxNiksIChLWzNdICYgMHhmZmZmMDAwMCkgfCAoS1swXSAmIDB4MDAwMGZmZmYpXG5cdCAgICAgICAgICAgIF07XG5cblx0ICAgICAgICAgICAgLy8gQ2FycnkgYml0XG5cdCAgICAgICAgICAgIHRoaXMuX2IgPSAwO1xuXG5cdCAgICAgICAgICAgIC8vIEl0ZXJhdGUgdGhlIHN5c3RlbSBmb3VyIHRpbWVzXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgNDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICBuZXh0U3RhdGUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIE1vZGlmeSB0aGUgY291bnRlcnNcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIENbaV0gXj0gWFsoaSArIDQpICYgN107XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBJViBzZXR1cFxuXHQgICAgICAgICAgICBpZiAoaXYpIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgdmFyIElWID0gaXYud29yZHM7XG5cdCAgICAgICAgICAgICAgICB2YXIgSVZfMCA9IElWWzBdO1xuXHQgICAgICAgICAgICAgICAgdmFyIElWXzEgPSBJVlsxXTtcblxuXHQgICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgZm91ciBzdWJ2ZWN0b3JzXG5cdCAgICAgICAgICAgICAgICB2YXIgaTAgPSAoKChJVl8wIDw8IDgpIHwgKElWXzAgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8ICgoKElWXzAgPDwgMjQpIHwgKElWXzAgPj4+IDgpKSAmIDB4ZmYwMGZmMDApO1xuXHQgICAgICAgICAgICAgICAgdmFyIGkyID0gKCgoSVZfMSA8PCA4KSB8IChJVl8xID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfCAoKChJVl8xIDw8IDI0KSB8IChJVl8xID4+PiA4KSkgJiAweGZmMDBmZjAwKTtcblx0ICAgICAgICAgICAgICAgIHZhciBpMSA9IChpMCA+Pj4gMTYpIHwgKGkyICYgMHhmZmZmMDAwMCk7XG5cdCAgICAgICAgICAgICAgICB2YXIgaTMgPSAoaTIgPDwgMTYpICB8IChpMCAmIDB4MDAwMGZmZmYpO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBNb2RpZnkgY291bnRlciB2YWx1ZXNcblx0ICAgICAgICAgICAgICAgIENbMF0gXj0gaTA7XG5cdCAgICAgICAgICAgICAgICBDWzFdIF49IGkxO1xuXHQgICAgICAgICAgICAgICAgQ1syXSBePSBpMjtcblx0ICAgICAgICAgICAgICAgIENbM10gXj0gaTM7XG5cdCAgICAgICAgICAgICAgICBDWzRdIF49IGkwO1xuXHQgICAgICAgICAgICAgICAgQ1s1XSBePSBpMTtcblx0ICAgICAgICAgICAgICAgIENbNl0gXj0gaTI7XG5cdCAgICAgICAgICAgICAgICBDWzddIF49IGkzO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBJdGVyYXRlIHRoZSBzeXN0ZW0gZm91ciB0aW1lc1xuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgICAgICBuZXh0U3RhdGUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9Qcm9jZXNzQmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIFggPSB0aGlzLl9YO1xuXG5cdCAgICAgICAgICAgIC8vIEl0ZXJhdGUgdGhlIHN5c3RlbVxuXHQgICAgICAgICAgICBuZXh0U3RhdGUuY2FsbCh0aGlzKTtcblxuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSBmb3VyIGtleXN0cmVhbSB3b3Jkc1xuXHQgICAgICAgICAgICBTWzBdID0gWFswXSBeIChYWzVdID4+PiAxNikgXiAoWFszXSA8PCAxNik7XG5cdCAgICAgICAgICAgIFNbMV0gPSBYWzJdIF4gKFhbN10gPj4+IDE2KSBeIChYWzVdIDw8IDE2KTtcblx0ICAgICAgICAgICAgU1syXSA9IFhbNF0gXiAoWFsxXSA+Pj4gMTYpIF4gKFhbN10gPDwgMTYpO1xuXHQgICAgICAgICAgICBTWzNdID0gWFs2XSBeIChYWzNdID4+PiAxNikgXiAoWFsxXSA8PCAxNik7XG5cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIC8vIFN3YXAgZW5kaWFuXG5cdCAgICAgICAgICAgICAgICBTW2ldID0gKCgoU1tpXSA8PCA4KSAgfCAoU1tpXSA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICAgICAgICAoKChTW2ldIDw8IDI0KSB8IChTW2ldID4+PiA4KSkgICYgMHhmZjAwZmYwMCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgICAgIE1bb2Zmc2V0ICsgaV0gXj0gU1tpXTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBibG9ja1NpemU6IDEyOC8zMixcblxuXHQgICAgICAgIGl2U2l6ZTogNjQvMzJcblx0ICAgIH0pO1xuXG5cdCAgICBmdW5jdGlvbiBuZXh0U3RhdGUoKSB7XG5cdCAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgdmFyIFggPSB0aGlzLl9YO1xuXHQgICAgICAgIHZhciBDID0gdGhpcy5fQztcblxuXHQgICAgICAgIC8vIFNhdmUgb2xkIGNvdW50ZXIgdmFsdWVzXG5cdCAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4OyBpKyspIHtcblx0ICAgICAgICAgICAgQ19baV0gPSBDW2ldO1xuXHQgICAgICAgIH1cblxuXHQgICAgICAgIC8vIENhbGN1bGF0ZSBuZXcgY291bnRlciB2YWx1ZXNcblx0ICAgICAgICBDWzBdID0gKENbMF0gKyAweDRkMzRkMzRkICsgdGhpcy5fYikgfCAwO1xuXHQgICAgICAgIENbMV0gPSAoQ1sxXSArIDB4ZDM0ZDM0ZDMgKyAoKENbMF0gPj4+IDApIDwgKENfWzBdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbMl0gPSAoQ1syXSArIDB4MzRkMzRkMzQgKyAoKENbMV0gPj4+IDApIDwgKENfWzFdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbM10gPSAoQ1szXSArIDB4NGQzNGQzNGQgKyAoKENbMl0gPj4+IDApIDwgKENfWzJdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbNF0gPSAoQ1s0XSArIDB4ZDM0ZDM0ZDMgKyAoKENbM10gPj4+IDApIDwgKENfWzNdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbNV0gPSAoQ1s1XSArIDB4MzRkMzRkMzQgKyAoKENbNF0gPj4+IDApIDwgKENfWzRdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbNl0gPSAoQ1s2XSArIDB4NGQzNGQzNGQgKyAoKENbNV0gPj4+IDApIDwgKENfWzVdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbN10gPSAoQ1s3XSArIDB4ZDM0ZDM0ZDMgKyAoKENbNl0gPj4+IDApIDwgKENfWzZdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIHRoaXMuX2IgPSAoQ1s3XSA+Pj4gMCkgPCAoQ19bN10gPj4+IDApID8gMSA6IDA7XG5cblx0ICAgICAgICAvLyBDYWxjdWxhdGUgdGhlIGctdmFsdWVzXG5cdCAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4OyBpKyspIHtcblx0ICAgICAgICAgICAgdmFyIGd4ID0gWFtpXSArIENbaV07XG5cblx0ICAgICAgICAgICAgLy8gQ29uc3RydWN0IGhpZ2ggYW5kIGxvdyBhcmd1bWVudCBmb3Igc3F1YXJpbmdcblx0ICAgICAgICAgICAgdmFyIGdhID0gZ3ggJiAweGZmZmY7XG5cdCAgICAgICAgICAgIHZhciBnYiA9IGd4ID4+PiAxNjtcblxuXHQgICAgICAgICAgICAvLyBDYWxjdWxhdGUgaGlnaCBhbmQgbG93IHJlc3VsdCBvZiBzcXVhcmluZ1xuXHQgICAgICAgICAgICB2YXIgZ2ggPSAoKCgoZ2EgKiBnYSkgPj4+IDE3KSArIGdhICogZ2IpID4+PiAxNSkgKyBnYiAqIGdiO1xuXHQgICAgICAgICAgICB2YXIgZ2wgPSAoKChneCAmIDB4ZmZmZjAwMDApICogZ3gpIHwgMCkgKyAoKChneCAmIDB4MDAwMGZmZmYpICogZ3gpIHwgMCk7XG5cblx0ICAgICAgICAgICAgLy8gSGlnaCBYT1IgbG93XG5cdCAgICAgICAgICAgIEdbaV0gPSBnaCBeIGdsO1xuXHQgICAgICAgIH1cblxuXHQgICAgICAgIC8vIENhbGN1bGF0ZSBuZXcgc3RhdGUgdmFsdWVzXG5cdCAgICAgICAgWFswXSA9IChHWzBdICsgKChHWzddIDw8IDE2KSB8IChHWzddID4+PiAxNikpICsgKChHWzZdIDw8IDE2KSB8IChHWzZdID4+PiAxNikpKSB8IDA7XG5cdCAgICAgICAgWFsxXSA9IChHWzFdICsgKChHWzBdIDw8IDgpICB8IChHWzBdID4+PiAyNCkpICsgR1s3XSkgfCAwO1xuXHQgICAgICAgIFhbMl0gPSAoR1syXSArICgoR1sxXSA8PCAxNikgfCAoR1sxXSA+Pj4gMTYpKSArICgoR1swXSA8PCAxNikgfCAoR1swXSA+Pj4gMTYpKSkgfCAwO1xuXHQgICAgICAgIFhbM10gPSAoR1szXSArICgoR1syXSA8PCA4KSAgfCAoR1syXSA+Pj4gMjQpKSArIEdbMV0pIHwgMDtcblx0ICAgICAgICBYWzRdID0gKEdbNF0gKyAoKEdbM10gPDwgMTYpIHwgKEdbM10gPj4+IDE2KSkgKyAoKEdbMl0gPDwgMTYpIHwgKEdbMl0gPj4+IDE2KSkpIHwgMDtcblx0ICAgICAgICBYWzVdID0gKEdbNV0gKyAoKEdbNF0gPDwgOCkgIHwgKEdbNF0gPj4+IDI0KSkgKyBHWzNdKSB8IDA7XG5cdCAgICAgICAgWFs2XSA9IChHWzZdICsgKChHWzVdIDw8IDE2KSB8IChHWzVdID4+PiAxNikpICsgKChHWzRdIDw8IDE2KSB8IChHWzRdID4+PiAxNikpKSB8IDA7XG5cdCAgICAgICAgWFs3XSA9IChHWzddICsgKChHWzZdIDw8IDgpICB8IChHWzZdID4+PiAyNCkpICsgR1s1XSkgfCAwO1xuXHQgICAgfVxuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9ucyB0byB0aGUgY2lwaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgY2lwaGVydGV4dCA9IENyeXB0b0pTLlJhYmJpdExlZ2FjeS5lbmNyeXB0KG1lc3NhZ2UsIGtleSwgY2ZnKTtcblx0ICAgICAqICAgICB2YXIgcGxhaW50ZXh0ICA9IENyeXB0b0pTLlJhYmJpdExlZ2FjeS5kZWNyeXB0KGNpcGhlcnRleHQsIGtleSwgY2ZnKTtcblx0ICAgICAqL1xuXHQgICAgQy5SYWJiaXRMZWdhY3kgPSBTdHJlYW1DaXBoZXIuX2NyZWF0ZUhlbHBlcihSYWJiaXRMZWdhY3kpO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLlJhYmJpdExlZ2FjeTtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9lbmMtYmFzZTY0XCIpLCByZXF1aXJlKFwiLi9tZDVcIiksIHJlcXVpcmUoXCIuL2V2cGtkZlwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vZW5jLWJhc2U2NFwiLCBcIi4vbWQ1XCIsIFwiLi9ldnBrZGZcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgU3RyZWFtQ2lwaGVyID0gQ19saWIuU3RyZWFtQ2lwaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gUmV1c2FibGUgb2JqZWN0c1xuXHQgICAgdmFyIFMgID0gW107XG5cdCAgICB2YXIgQ18gPSBbXTtcblx0ICAgIHZhciBHICA9IFtdO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFJhYmJpdCBzdHJlYW0gY2lwaGVyIGFsZ29yaXRobVxuXHQgICAgICovXG5cdCAgICB2YXIgUmFiYml0ID0gQ19hbGdvLlJhYmJpdCA9IFN0cmVhbUNpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgSyA9IHRoaXMuX2tleS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIGl2ID0gdGhpcy5jZmcuaXY7XG5cblx0ICAgICAgICAgICAgLy8gU3dhcCBlbmRpYW5cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIEtbaV0gPSAoKChLW2ldIDw8IDgpICB8IChLW2ldID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgICAgICAgICgoKEtbaV0gPDwgMjQpIHwgKEtbaV0gPj4+IDgpKSAgJiAweGZmMDBmZjAwKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEdlbmVyYXRlIGluaXRpYWwgc3RhdGUgdmFsdWVzXG5cdCAgICAgICAgICAgIHZhciBYID0gdGhpcy5fWCA9IFtcblx0ICAgICAgICAgICAgICAgIEtbMF0sIChLWzNdIDw8IDE2KSB8IChLWzJdID4+PiAxNiksXG5cdCAgICAgICAgICAgICAgICBLWzFdLCAoS1swXSA8PCAxNikgfCAoS1szXSA+Pj4gMTYpLFxuXHQgICAgICAgICAgICAgICAgS1syXSwgKEtbMV0gPDwgMTYpIHwgKEtbMF0gPj4+IDE2KSxcblx0ICAgICAgICAgICAgICAgIEtbM10sIChLWzJdIDw8IDE2KSB8IChLWzFdID4+PiAxNilcblx0ICAgICAgICAgICAgXTtcblxuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSBpbml0aWFsIGNvdW50ZXIgdmFsdWVzXG5cdCAgICAgICAgICAgIHZhciBDID0gdGhpcy5fQyA9IFtcblx0ICAgICAgICAgICAgICAgIChLWzJdIDw8IDE2KSB8IChLWzJdID4+PiAxNiksIChLWzBdICYgMHhmZmZmMDAwMCkgfCAoS1sxXSAmIDB4MDAwMGZmZmYpLFxuXHQgICAgICAgICAgICAgICAgKEtbM10gPDwgMTYpIHwgKEtbM10gPj4+IDE2KSwgKEtbMV0gJiAweGZmZmYwMDAwKSB8IChLWzJdICYgMHgwMDAwZmZmZiksXG5cdCAgICAgICAgICAgICAgICAoS1swXSA8PCAxNikgfCAoS1swXSA+Pj4gMTYpLCAoS1syXSAmIDB4ZmZmZjAwMDApIHwgKEtbM10gJiAweDAwMDBmZmZmKSxcblx0ICAgICAgICAgICAgICAgIChLWzFdIDw8IDE2KSB8IChLWzFdID4+PiAxNiksIChLWzNdICYgMHhmZmZmMDAwMCkgfCAoS1swXSAmIDB4MDAwMGZmZmYpXG5cdCAgICAgICAgICAgIF07XG5cblx0ICAgICAgICAgICAgLy8gQ2FycnkgYml0XG5cdCAgICAgICAgICAgIHRoaXMuX2IgPSAwO1xuXG5cdCAgICAgICAgICAgIC8vIEl0ZXJhdGUgdGhlIHN5c3RlbSBmb3VyIHRpbWVzXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgNDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICBuZXh0U3RhdGUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIE1vZGlmeSB0aGUgY291bnRlcnNcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIENbaV0gXj0gWFsoaSArIDQpICYgN107XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBJViBzZXR1cFxuXHQgICAgICAgICAgICBpZiAoaXYpIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgdmFyIElWID0gaXYud29yZHM7XG5cdCAgICAgICAgICAgICAgICB2YXIgSVZfMCA9IElWWzBdO1xuXHQgICAgICAgICAgICAgICAgdmFyIElWXzEgPSBJVlsxXTtcblxuXHQgICAgICAgICAgICAgICAgLy8gR2VuZXJhdGUgZm91ciBzdWJ2ZWN0b3JzXG5cdCAgICAgICAgICAgICAgICB2YXIgaTAgPSAoKChJVl8wIDw8IDgpIHwgKElWXzAgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8ICgoKElWXzAgPDwgMjQpIHwgKElWXzAgPj4+IDgpKSAmIDB4ZmYwMGZmMDApO1xuXHQgICAgICAgICAgICAgICAgdmFyIGkyID0gKCgoSVZfMSA8PCA4KSB8IChJVl8xID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfCAoKChJVl8xIDw8IDI0KSB8IChJVl8xID4+PiA4KSkgJiAweGZmMDBmZjAwKTtcblx0ICAgICAgICAgICAgICAgIHZhciBpMSA9IChpMCA+Pj4gMTYpIHwgKGkyICYgMHhmZmZmMDAwMCk7XG5cdCAgICAgICAgICAgICAgICB2YXIgaTMgPSAoaTIgPDwgMTYpICB8IChpMCAmIDB4MDAwMGZmZmYpO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBNb2RpZnkgY291bnRlciB2YWx1ZXNcblx0ICAgICAgICAgICAgICAgIENbMF0gXj0gaTA7XG5cdCAgICAgICAgICAgICAgICBDWzFdIF49IGkxO1xuXHQgICAgICAgICAgICAgICAgQ1syXSBePSBpMjtcblx0ICAgICAgICAgICAgICAgIENbM10gXj0gaTM7XG5cdCAgICAgICAgICAgICAgICBDWzRdIF49IGkwO1xuXHQgICAgICAgICAgICAgICAgQ1s1XSBePSBpMTtcblx0ICAgICAgICAgICAgICAgIENbNl0gXj0gaTI7XG5cdCAgICAgICAgICAgICAgICBDWzddIF49IGkzO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBJdGVyYXRlIHRoZSBzeXN0ZW0gZm91ciB0aW1lc1xuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgICAgICBuZXh0U3RhdGUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9Qcm9jZXNzQmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIFggPSB0aGlzLl9YO1xuXG5cdCAgICAgICAgICAgIC8vIEl0ZXJhdGUgdGhlIHN5c3RlbVxuXHQgICAgICAgICAgICBuZXh0U3RhdGUuY2FsbCh0aGlzKTtcblxuXHQgICAgICAgICAgICAvLyBHZW5lcmF0ZSBmb3VyIGtleXN0cmVhbSB3b3Jkc1xuXHQgICAgICAgICAgICBTWzBdID0gWFswXSBeIChYWzVdID4+PiAxNikgXiAoWFszXSA8PCAxNik7XG5cdCAgICAgICAgICAgIFNbMV0gPSBYWzJdIF4gKFhbN10gPj4+IDE2KSBeIChYWzVdIDw8IDE2KTtcblx0ICAgICAgICAgICAgU1syXSA9IFhbNF0gXiAoWFsxXSA+Pj4gMTYpIF4gKFhbN10gPDwgMTYpO1xuXHQgICAgICAgICAgICBTWzNdID0gWFs2XSBeIChYWzNdID4+PiAxNikgXiAoWFsxXSA8PCAxNik7XG5cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA0OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIC8vIFN3YXAgZW5kaWFuXG5cdCAgICAgICAgICAgICAgICBTW2ldID0gKCgoU1tpXSA8PCA4KSAgfCAoU1tpXSA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICAgICAgICAoKChTW2ldIDw8IDI0KSB8IChTW2ldID4+PiA4KSkgICYgMHhmZjAwZmYwMCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIEVuY3J5cHRcblx0ICAgICAgICAgICAgICAgIE1bb2Zmc2V0ICsgaV0gXj0gU1tpXTtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBibG9ja1NpemU6IDEyOC8zMixcblxuXHQgICAgICAgIGl2U2l6ZTogNjQvMzJcblx0ICAgIH0pO1xuXG5cdCAgICBmdW5jdGlvbiBuZXh0U3RhdGUoKSB7XG5cdCAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgdmFyIFggPSB0aGlzLl9YO1xuXHQgICAgICAgIHZhciBDID0gdGhpcy5fQztcblxuXHQgICAgICAgIC8vIFNhdmUgb2xkIGNvdW50ZXIgdmFsdWVzXG5cdCAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4OyBpKyspIHtcblx0ICAgICAgICAgICAgQ19baV0gPSBDW2ldO1xuXHQgICAgICAgIH1cblxuXHQgICAgICAgIC8vIENhbGN1bGF0ZSBuZXcgY291bnRlciB2YWx1ZXNcblx0ICAgICAgICBDWzBdID0gKENbMF0gKyAweDRkMzRkMzRkICsgdGhpcy5fYikgfCAwO1xuXHQgICAgICAgIENbMV0gPSAoQ1sxXSArIDB4ZDM0ZDM0ZDMgKyAoKENbMF0gPj4+IDApIDwgKENfWzBdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbMl0gPSAoQ1syXSArIDB4MzRkMzRkMzQgKyAoKENbMV0gPj4+IDApIDwgKENfWzFdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbM10gPSAoQ1szXSArIDB4NGQzNGQzNGQgKyAoKENbMl0gPj4+IDApIDwgKENfWzJdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbNF0gPSAoQ1s0XSArIDB4ZDM0ZDM0ZDMgKyAoKENbM10gPj4+IDApIDwgKENfWzNdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbNV0gPSAoQ1s1XSArIDB4MzRkMzRkMzQgKyAoKENbNF0gPj4+IDApIDwgKENfWzRdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbNl0gPSAoQ1s2XSArIDB4NGQzNGQzNGQgKyAoKENbNV0gPj4+IDApIDwgKENfWzVdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIENbN10gPSAoQ1s3XSArIDB4ZDM0ZDM0ZDMgKyAoKENbNl0gPj4+IDApIDwgKENfWzZdID4+PiAwKSA/IDEgOiAwKSkgfCAwO1xuXHQgICAgICAgIHRoaXMuX2IgPSAoQ1s3XSA+Pj4gMCkgPCAoQ19bN10gPj4+IDApID8gMSA6IDA7XG5cblx0ICAgICAgICAvLyBDYWxjdWxhdGUgdGhlIGctdmFsdWVzXG5cdCAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4OyBpKyspIHtcblx0ICAgICAgICAgICAgdmFyIGd4ID0gWFtpXSArIENbaV07XG5cblx0ICAgICAgICAgICAgLy8gQ29uc3RydWN0IGhpZ2ggYW5kIGxvdyBhcmd1bWVudCBmb3Igc3F1YXJpbmdcblx0ICAgICAgICAgICAgdmFyIGdhID0gZ3ggJiAweGZmZmY7XG5cdCAgICAgICAgICAgIHZhciBnYiA9IGd4ID4+PiAxNjtcblxuXHQgICAgICAgICAgICAvLyBDYWxjdWxhdGUgaGlnaCBhbmQgbG93IHJlc3VsdCBvZiBzcXVhcmluZ1xuXHQgICAgICAgICAgICB2YXIgZ2ggPSAoKCgoZ2EgKiBnYSkgPj4+IDE3KSArIGdhICogZ2IpID4+PiAxNSkgKyBnYiAqIGdiO1xuXHQgICAgICAgICAgICB2YXIgZ2wgPSAoKChneCAmIDB4ZmZmZjAwMDApICogZ3gpIHwgMCkgKyAoKChneCAmIDB4MDAwMGZmZmYpICogZ3gpIHwgMCk7XG5cblx0ICAgICAgICAgICAgLy8gSGlnaCBYT1IgbG93XG5cdCAgICAgICAgICAgIEdbaV0gPSBnaCBeIGdsO1xuXHQgICAgICAgIH1cblxuXHQgICAgICAgIC8vIENhbGN1bGF0ZSBuZXcgc3RhdGUgdmFsdWVzXG5cdCAgICAgICAgWFswXSA9IChHWzBdICsgKChHWzddIDw8IDE2KSB8IChHWzddID4+PiAxNikpICsgKChHWzZdIDw8IDE2KSB8IChHWzZdID4+PiAxNikpKSB8IDA7XG5cdCAgICAgICAgWFsxXSA9IChHWzFdICsgKChHWzBdIDw8IDgpICB8IChHWzBdID4+PiAyNCkpICsgR1s3XSkgfCAwO1xuXHQgICAgICAgIFhbMl0gPSAoR1syXSArICgoR1sxXSA8PCAxNikgfCAoR1sxXSA+Pj4gMTYpKSArICgoR1swXSA8PCAxNikgfCAoR1swXSA+Pj4gMTYpKSkgfCAwO1xuXHQgICAgICAgIFhbM10gPSAoR1szXSArICgoR1syXSA8PCA4KSAgfCAoR1syXSA+Pj4gMjQpKSArIEdbMV0pIHwgMDtcblx0ICAgICAgICBYWzRdID0gKEdbNF0gKyAoKEdbM10gPDwgMTYpIHwgKEdbM10gPj4+IDE2KSkgKyAoKEdbMl0gPDwgMTYpIHwgKEdbMl0gPj4+IDE2KSkpIHwgMDtcblx0ICAgICAgICBYWzVdID0gKEdbNV0gKyAoKEdbNF0gPDwgOCkgIHwgKEdbNF0gPj4+IDI0KSkgKyBHWzNdKSB8IDA7XG5cdCAgICAgICAgWFs2XSA9IChHWzZdICsgKChHWzVdIDw8IDE2KSB8IChHWzVdID4+PiAxNikpICsgKChHWzRdIDw8IDE2KSB8IChHWzRdID4+PiAxNikpKSB8IDA7XG5cdCAgICAgICAgWFs3XSA9IChHWzddICsgKChHWzZdIDw8IDgpICB8IChHWzZdID4+PiAyNCkpICsgR1s1XSkgfCAwO1xuXHQgICAgfVxuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9ucyB0byB0aGUgY2lwaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgY2lwaGVydGV4dCA9IENyeXB0b0pTLlJhYmJpdC5lbmNyeXB0KG1lc3NhZ2UsIGtleSwgY2ZnKTtcblx0ICAgICAqICAgICB2YXIgcGxhaW50ZXh0ICA9IENyeXB0b0pTLlJhYmJpdC5kZWNyeXB0KGNpcGhlcnRleHQsIGtleSwgY2ZnKTtcblx0ICAgICAqL1xuXHQgICAgQy5SYWJiaXQgPSBTdHJlYW1DaXBoZXIuX2NyZWF0ZUhlbHBlcihSYWJiaXQpO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLlJhYmJpdDtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9lbmMtYmFzZTY0XCIpLCByZXF1aXJlKFwiLi9tZDVcIiksIHJlcXVpcmUoXCIuL2V2cGtkZlwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vZW5jLWJhc2U2NFwiLCBcIi4vbWQ1XCIsIFwiLi9ldnBrZGZcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgU3RyZWFtQ2lwaGVyID0gQ19saWIuU3RyZWFtQ2lwaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLyoqXG5cdCAgICAgKiBSQzQgc3RyZWFtIGNpcGhlciBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBSQzQgPSBDX2FsZ28uUkM0ID0gU3RyZWFtQ2lwaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgX2RvUmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBrZXkgPSB0aGlzLl9rZXk7XG5cdCAgICAgICAgICAgIHZhciBrZXlXb3JkcyA9IGtleS53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIGtleVNpZ0J5dGVzID0ga2V5LnNpZ0J5dGVzO1xuXG5cdCAgICAgICAgICAgIC8vIEluaXQgc2JveFxuXHQgICAgICAgICAgICB2YXIgUyA9IHRoaXMuX1MgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNTY7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgU1tpXSA9IGk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBLZXkgc2V0dXBcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDAsIGogPSAwOyBpIDwgMjU2OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHZhciBrZXlCeXRlSW5kZXggPSBpICUga2V5U2lnQnl0ZXM7XG5cdCAgICAgICAgICAgICAgICB2YXIga2V5Qnl0ZSA9IChrZXlXb3Jkc1trZXlCeXRlSW5kZXggPj4+IDJdID4+PiAoMjQgLSAoa2V5Qnl0ZUluZGV4ICUgNCkgKiA4KSkgJiAweGZmO1xuXG5cdCAgICAgICAgICAgICAgICBqID0gKGogKyBTW2ldICsga2V5Qnl0ZSkgJSAyNTY7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFN3YXBcblx0ICAgICAgICAgICAgICAgIHZhciB0ID0gU1tpXTtcblx0ICAgICAgICAgICAgICAgIFNbaV0gPSBTW2pdO1xuXHQgICAgICAgICAgICAgICAgU1tqXSA9IHQ7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBDb3VudGVyc1xuXHQgICAgICAgICAgICB0aGlzLl9pID0gdGhpcy5faiA9IDA7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICBNW29mZnNldF0gXj0gZ2VuZXJhdGVLZXlzdHJlYW1Xb3JkLmNhbGwodGhpcyk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGtleVNpemU6IDI1Ni8zMixcblxuXHQgICAgICAgIGl2U2l6ZTogMFxuXHQgICAgfSk7XG5cblx0ICAgIGZ1bmN0aW9uIGdlbmVyYXRlS2V5c3RyZWFtV29yZCgpIHtcblx0ICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICB2YXIgUyA9IHRoaXMuX1M7XG5cdCAgICAgICAgdmFyIGkgPSB0aGlzLl9pO1xuXHQgICAgICAgIHZhciBqID0gdGhpcy5fajtcblxuXHQgICAgICAgIC8vIEdlbmVyYXRlIGtleXN0cmVhbSB3b3JkXG5cdCAgICAgICAgdmFyIGtleXN0cmVhbVdvcmQgPSAwO1xuXHQgICAgICAgIGZvciAodmFyIG4gPSAwOyBuIDwgNDsgbisrKSB7XG5cdCAgICAgICAgICAgIGkgPSAoaSArIDEpICUgMjU2O1xuXHQgICAgICAgICAgICBqID0gKGogKyBTW2ldKSAlIDI1NjtcblxuXHQgICAgICAgICAgICAvLyBTd2FwXG5cdCAgICAgICAgICAgIHZhciB0ID0gU1tpXTtcblx0ICAgICAgICAgICAgU1tpXSA9IFNbal07XG5cdCAgICAgICAgICAgIFNbal0gPSB0O1xuXG5cdCAgICAgICAgICAgIGtleXN0cmVhbVdvcmQgfD0gU1soU1tpXSArIFNbal0pICUgMjU2XSA8PCAoMjQgLSBuICogOCk7XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gVXBkYXRlIGNvdW50ZXJzXG5cdCAgICAgICAgdGhpcy5faSA9IGk7XG5cdCAgICAgICAgdGhpcy5faiA9IGo7XG5cblx0ICAgICAgICByZXR1cm4ga2V5c3RyZWFtV29yZDtcblx0ICAgIH1cblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbnMgdG8gdGhlIGNpcGhlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGNpcGhlcnRleHQgPSBDcnlwdG9KUy5SQzQuZW5jcnlwdChtZXNzYWdlLCBrZXksIGNmZyk7XG5cdCAgICAgKiAgICAgdmFyIHBsYWludGV4dCAgPSBDcnlwdG9KUy5SQzQuZGVjcnlwdChjaXBoZXJ0ZXh0LCBrZXksIGNmZyk7XG5cdCAgICAgKi9cblx0ICAgIEMuUkM0ID0gU3RyZWFtQ2lwaGVyLl9jcmVhdGVIZWxwZXIoUkM0KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBNb2RpZmllZCBSQzQgc3RyZWFtIGNpcGhlciBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBSQzREcm9wID0gQ19hbGdvLlJDNERyb3AgPSBSQzQuZXh0ZW5kKHtcblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb25maWd1cmF0aW9uIG9wdGlvbnMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcHJvcGVydHkge251bWJlcn0gZHJvcCBUaGUgbnVtYmVyIG9mIGtleXN0cmVhbSB3b3JkcyB0byBkcm9wLiBEZWZhdWx0IDE5MlxuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGNmZzogUkM0LmNmZy5leHRlbmQoe1xuXHQgICAgICAgICAgICBkcm9wOiAxOTJcblx0ICAgICAgICB9KSxcblxuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIFJDNC5fZG9SZXNldC5jYWxsKHRoaXMpO1xuXG5cdCAgICAgICAgICAgIC8vIERyb3Bcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IHRoaXMuY2ZnLmRyb3A7IGkgPiAwOyBpLS0pIHtcblx0ICAgICAgICAgICAgICAgIGdlbmVyYXRlS2V5c3RyZWFtV29yZC5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb25zIHRvIHRoZSBjaXBoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0ID0gQ3J5cHRvSlMuUkM0RHJvcC5lbmNyeXB0KG1lc3NhZ2UsIGtleSwgY2ZnKTtcblx0ICAgICAqICAgICB2YXIgcGxhaW50ZXh0ICA9IENyeXB0b0pTLlJDNERyb3AuZGVjcnlwdChjaXBoZXJ0ZXh0LCBrZXksIGNmZyk7XG5cdCAgICAgKi9cblx0ICAgIEMuUkM0RHJvcCA9IFN0cmVhbUNpcGhlci5fY3JlYXRlSGVscGVyKFJDNERyb3ApO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLlJDNDtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0LyoqIEBwcmVzZXJ2ZVxuXHQoYykgMjAxMiBieSBDw6lkcmljIE1lc25pbC4gQWxsIHJpZ2h0cyByZXNlcnZlZC5cblxuXHRSZWRpc3RyaWJ1dGlvbiBhbmQgdXNlIGluIHNvdXJjZSBhbmQgYmluYXJ5IGZvcm1zLCB3aXRoIG9yIHdpdGhvdXQgbW9kaWZpY2F0aW9uLCBhcmUgcGVybWl0dGVkIHByb3ZpZGVkIHRoYXQgdGhlIGZvbGxvd2luZyBjb25kaXRpb25zIGFyZSBtZXQ6XG5cblx0ICAgIC0gUmVkaXN0cmlidXRpb25zIG9mIHNvdXJjZSBjb2RlIG11c3QgcmV0YWluIHRoZSBhYm92ZSBjb3B5cmlnaHQgbm90aWNlLCB0aGlzIGxpc3Qgb2YgY29uZGl0aW9ucyBhbmQgdGhlIGZvbGxvd2luZyBkaXNjbGFpbWVyLlxuXHQgICAgLSBSZWRpc3RyaWJ1dGlvbnMgaW4gYmluYXJ5IGZvcm0gbXVzdCByZXByb2R1Y2UgdGhlIGFib3ZlIGNvcHlyaWdodCBub3RpY2UsIHRoaXMgbGlzdCBvZiBjb25kaXRpb25zIGFuZCB0aGUgZm9sbG93aW5nIGRpc2NsYWltZXIgaW4gdGhlIGRvY3VtZW50YXRpb24gYW5kL29yIG90aGVyIG1hdGVyaWFscyBwcm92aWRlZCB3aXRoIHRoZSBkaXN0cmlidXRpb24uXG5cblx0VEhJUyBTT0ZUV0FSRSBJUyBQUk9WSURFRCBCWSBUSEUgQ09QWVJJR0hUIEhPTERFUlMgQU5EIENPTlRSSUJVVE9SUyBcIkFTIElTXCIgQU5EIEFOWSBFWFBSRVNTIE9SIElNUExJRUQgV0FSUkFOVElFUywgSU5DTFVESU5HLCBCVVQgTk9UIExJTUlURUQgVE8sIFRIRSBJTVBMSUVEIFdBUlJBTlRJRVMgT0YgTUVSQ0hBTlRBQklMSVRZIEFORCBGSVRORVNTIEZPUiBBIFBBUlRJQ1VMQVIgUFVSUE9TRSBBUkUgRElTQ0xBSU1FRC4gSU4gTk8gRVZFTlQgU0hBTEwgVEhFIENPUFlSSUdIVCBIT0xERVIgT1IgQ09OVFJJQlVUT1JTIEJFIExJQUJMRSBGT1IgQU5ZIERJUkVDVCwgSU5ESVJFQ1QsIElOQ0lERU5UQUwsIFNQRUNJQUwsIEVYRU1QTEFSWSwgT1IgQ09OU0VRVUVOVElBTCBEQU1BR0VTIChJTkNMVURJTkcsIEJVVCBOT1QgTElNSVRFRCBUTywgUFJPQ1VSRU1FTlQgT0YgU1VCU1RJVFVURSBHT09EUyBPUiBTRVJWSUNFUzsgTE9TUyBPRiBVU0UsIERBVEEsIE9SIFBST0ZJVFM7IE9SIEJVU0lORVNTIElOVEVSUlVQVElPTikgSE9XRVZFUiBDQVVTRUQgQU5EIE9OIEFOWSBUSEVPUlkgT0YgTElBQklMSVRZLCBXSEVUSEVSIElOIENPTlRSQUNULCBTVFJJQ1QgTElBQklMSVRZLCBPUiBUT1JUIChJTkNMVURJTkcgTkVHTElHRU5DRSBPUiBPVEhFUldJU0UpIEFSSVNJTkcgSU4gQU5ZIFdBWSBPVVQgT0YgVEhFIFVTRSBPRiBUSElTIFNPRlRXQVJFLCBFVkVOIElGIEFEVklTRUQgT0YgVEhFIFBPU1NJQklMSVRZIE9GIFNVQ0ggREFNQUdFLlxuXHQqL1xuXG5cdChmdW5jdGlvbiAoTWF0aCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5O1xuXHQgICAgdmFyIEhhc2hlciA9IENfbGliLkhhc2hlcjtcblx0ICAgIHZhciBDX2FsZ28gPSBDLmFsZ287XG5cblx0ICAgIC8vIENvbnN0YW50cyB0YWJsZVxuXHQgICAgdmFyIF96bCA9IFdvcmRBcnJheS5jcmVhdGUoW1xuXHQgICAgICAgIDAsICAxLCAgMiwgIDMsICA0LCAgNSwgIDYsICA3LCAgOCwgIDksIDEwLCAxMSwgMTIsIDEzLCAxNCwgMTUsXG5cdCAgICAgICAgNywgIDQsIDEzLCAgMSwgMTAsICA2LCAxNSwgIDMsIDEyLCAgMCwgIDksICA1LCAgMiwgMTQsIDExLCAgOCxcblx0ICAgICAgICAzLCAxMCwgMTQsICA0LCAgOSwgMTUsICA4LCAgMSwgIDIsICA3LCAgMCwgIDYsIDEzLCAxMSwgIDUsIDEyLFxuXHQgICAgICAgIDEsICA5LCAxMSwgMTAsICAwLCAgOCwgMTIsICA0LCAxMywgIDMsICA3LCAxNSwgMTQsICA1LCAgNiwgIDIsXG5cdCAgICAgICAgNCwgIDAsICA1LCAgOSwgIDcsIDEyLCAgMiwgMTAsIDE0LCAgMSwgIDMsICA4LCAxMSwgIDYsIDE1LCAxM10pO1xuXHQgICAgdmFyIF96ciA9IFdvcmRBcnJheS5jcmVhdGUoW1xuXHQgICAgICAgIDUsIDE0LCAgNywgIDAsICA5LCAgMiwgMTEsICA0LCAxMywgIDYsIDE1LCAgOCwgIDEsIDEwLCAgMywgMTIsXG5cdCAgICAgICAgNiwgMTEsICAzLCAgNywgIDAsIDEzLCAgNSwgMTAsIDE0LCAxNSwgIDgsIDEyLCAgNCwgIDksICAxLCAgMixcblx0ICAgICAgICAxNSwgIDUsICAxLCAgMywgIDcsIDE0LCAgNiwgIDksIDExLCAgOCwgMTIsICAyLCAxMCwgIDAsICA0LCAxMyxcblx0ICAgICAgICA4LCAgNiwgIDQsICAxLCAgMywgMTEsIDE1LCAgMCwgIDUsIDEyLCAgMiwgMTMsICA5LCAgNywgMTAsIDE0LFxuXHQgICAgICAgIDEyLCAxNSwgMTAsICA0LCAgMSwgIDUsICA4LCAgNywgIDYsICAyLCAxMywgMTQsICAwLCAgMywgIDksIDExXSk7XG5cdCAgICB2YXIgX3NsID0gV29yZEFycmF5LmNyZWF0ZShbXG5cdCAgICAgICAgIDExLCAxNCwgMTUsIDEyLCAgNSwgIDgsICA3LCAgOSwgMTEsIDEzLCAxNCwgMTUsICA2LCAgNywgIDksICA4LFxuXHQgICAgICAgIDcsIDYsICAgOCwgMTMsIDExLCAgOSwgIDcsIDE1LCAgNywgMTIsIDE1LCAgOSwgMTEsICA3LCAxMywgMTIsXG5cdCAgICAgICAgMTEsIDEzLCAgNiwgIDcsIDE0LCAgOSwgMTMsIDE1LCAxNCwgIDgsIDEzLCAgNiwgIDUsIDEyLCAgNywgIDUsXG5cdCAgICAgICAgICAxMSwgMTIsIDE0LCAxNSwgMTQsIDE1LCAgOSwgIDgsICA5LCAxNCwgIDUsICA2LCAgOCwgIDYsICA1LCAxMixcblx0ICAgICAgICA5LCAxNSwgIDUsIDExLCAgNiwgIDgsIDEzLCAxMiwgIDUsIDEyLCAxMywgMTQsIDExLCAgOCwgIDUsICA2IF0pO1xuXHQgICAgdmFyIF9zciA9IFdvcmRBcnJheS5jcmVhdGUoW1xuXHQgICAgICAgIDgsICA5LCAgOSwgMTEsIDEzLCAxNSwgMTUsICA1LCAgNywgIDcsICA4LCAxMSwgMTQsIDE0LCAxMiwgIDYsXG5cdCAgICAgICAgOSwgMTMsIDE1LCAgNywgMTIsICA4LCAgOSwgMTEsICA3LCAgNywgMTIsICA3LCAgNiwgMTUsIDEzLCAxMSxcblx0ICAgICAgICA5LCAgNywgMTUsIDExLCAgOCwgIDYsICA2LCAxNCwgMTIsIDEzLCAgNSwgMTQsIDEzLCAxMywgIDcsICA1LFxuXHQgICAgICAgIDE1LCAgNSwgIDgsIDExLCAxNCwgMTQsICA2LCAxNCwgIDYsICA5LCAxMiwgIDksIDEyLCAgNSwgMTUsICA4LFxuXHQgICAgICAgIDgsICA1LCAxMiwgIDksIDEyLCAgNSwgMTQsICA2LCAgOCwgMTMsICA2LCAgNSwgMTUsIDEzLCAxMSwgMTEgXSk7XG5cblx0ICAgIHZhciBfaGwgPSAgV29yZEFycmF5LmNyZWF0ZShbIDB4MDAwMDAwMDAsIDB4NUE4Mjc5OTksIDB4NkVEOUVCQTEsIDB4OEYxQkJDREMsIDB4QTk1M0ZENEVdKTtcblx0ICAgIHZhciBfaHIgPSAgV29yZEFycmF5LmNyZWF0ZShbIDB4NTBBMjhCRTYsIDB4NUM0REQxMjQsIDB4NkQ3MDNFRjMsIDB4N0E2RDc2RTksIDB4MDAwMDAwMDBdKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBSSVBFTUQxNjAgaGFzaCBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBSSVBFTUQxNjAgPSBDX2FsZ28uUklQRU1EMTYwID0gSGFzaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgX2RvUmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdGhpcy5faGFzaCAgPSBXb3JkQXJyYXkuY3JlYXRlKFsweDY3NDUyMzAxLCAweEVGQ0RBQjg5LCAweDk4QkFEQ0ZFLCAweDEwMzI1NDc2LCAweEMzRDJFMUYwXSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXG5cdCAgICAgICAgICAgIC8vIFN3YXAgZW5kaWFuXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMTY7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgICAgICB2YXIgb2Zmc2V0X2kgPSBvZmZzZXQgKyBpO1xuXHQgICAgICAgICAgICAgICAgdmFyIE1fb2Zmc2V0X2kgPSBNW29mZnNldF9pXTtcblxuXHQgICAgICAgICAgICAgICAgLy8gU3dhcFxuXHQgICAgICAgICAgICAgICAgTVtvZmZzZXRfaV0gPSAoXG5cdCAgICAgICAgICAgICAgICAgICAgKCgoTV9vZmZzZXRfaSA8PCA4KSAgfCAoTV9vZmZzZXRfaSA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICAgICAoKChNX29mZnNldF9pIDw8IDI0KSB8IChNX29mZnNldF9pID4+PiA4KSkgICYgMHhmZjAwZmYwMClcblx0ICAgICAgICAgICAgICAgICk7XG5cdCAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIEggID0gdGhpcy5faGFzaC53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIGhsID0gX2hsLndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgaHIgPSBfaHIud29yZHM7XG5cdCAgICAgICAgICAgIHZhciB6bCA9IF96bC53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHpyID0gX3pyLndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgc2wgPSBfc2wud29yZHM7XG5cdCAgICAgICAgICAgIHZhciBzciA9IF9zci53b3JkcztcblxuXHQgICAgICAgICAgICAvLyBXb3JraW5nIHZhcmlhYmxlc1xuXHQgICAgICAgICAgICB2YXIgYWwsIGJsLCBjbCwgZGwsIGVsO1xuXHQgICAgICAgICAgICB2YXIgYXIsIGJyLCBjciwgZHIsIGVyO1xuXG5cdCAgICAgICAgICAgIGFyID0gYWwgPSBIWzBdO1xuXHQgICAgICAgICAgICBiciA9IGJsID0gSFsxXTtcblx0ICAgICAgICAgICAgY3IgPSBjbCA9IEhbMl07XG5cdCAgICAgICAgICAgIGRyID0gZGwgPSBIWzNdO1xuXHQgICAgICAgICAgICBlciA9IGVsID0gSFs0XTtcblx0ICAgICAgICAgICAgLy8gQ29tcHV0YXRpb25cblx0ICAgICAgICAgICAgdmFyIHQ7XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgODA7IGkgKz0gMSkge1xuXHQgICAgICAgICAgICAgICAgdCA9IChhbCArICBNW29mZnNldCt6bFtpXV0pfDA7XG5cdCAgICAgICAgICAgICAgICBpZiAoaTwxNil7XG5cdFx0ICAgICAgICAgICAgdCArPSAgZjEoYmwsY2wsZGwpICsgaGxbMF07XG5cdCAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKGk8MzIpIHtcblx0XHQgICAgICAgICAgICB0ICs9ICBmMihibCxjbCxkbCkgKyBobFsxXTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoaTw0OCkge1xuXHRcdCAgICAgICAgICAgIHQgKz0gIGYzKGJsLGNsLGRsKSArIGhsWzJdO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChpPDY0KSB7XG5cdFx0ICAgICAgICAgICAgdCArPSAgZjQoYmwsY2wsZGwpICsgaGxbM107XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Ugey8vIGlmIChpPDgwKSB7XG5cdFx0ICAgICAgICAgICAgdCArPSAgZjUoYmwsY2wsZGwpICsgaGxbNF07XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgICAgICB0ID0gdHwwO1xuXHQgICAgICAgICAgICAgICAgdCA9ICByb3RsKHQsc2xbaV0pO1xuXHQgICAgICAgICAgICAgICAgdCA9ICh0K2VsKXwwO1xuXHQgICAgICAgICAgICAgICAgYWwgPSBlbDtcblx0ICAgICAgICAgICAgICAgIGVsID0gZGw7XG5cdCAgICAgICAgICAgICAgICBkbCA9IHJvdGwoY2wsIDEwKTtcblx0ICAgICAgICAgICAgICAgIGNsID0gYmw7XG5cdCAgICAgICAgICAgICAgICBibCA9IHQ7XG5cblx0ICAgICAgICAgICAgICAgIHQgPSAoYXIgKyBNW29mZnNldCt6cltpXV0pfDA7XG5cdCAgICAgICAgICAgICAgICBpZiAoaTwxNil7XG5cdFx0ICAgICAgICAgICAgdCArPSAgZjUoYnIsY3IsZHIpICsgaHJbMF07XG5cdCAgICAgICAgICAgICAgICB9IGVsc2UgaWYgKGk8MzIpIHtcblx0XHQgICAgICAgICAgICB0ICs9ICBmNChicixjcixkcikgKyBoclsxXTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoaTw0OCkge1xuXHRcdCAgICAgICAgICAgIHQgKz0gIGYzKGJyLGNyLGRyKSArIGhyWzJdO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChpPDY0KSB7XG5cdFx0ICAgICAgICAgICAgdCArPSAgZjIoYnIsY3IsZHIpICsgaHJbM107XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Ugey8vIGlmIChpPDgwKSB7XG5cdFx0ICAgICAgICAgICAgdCArPSAgZjEoYnIsY3IsZHIpICsgaHJbNF07XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgICAgICB0ID0gdHwwO1xuXHQgICAgICAgICAgICAgICAgdCA9ICByb3RsKHQsc3JbaV0pIDtcblx0ICAgICAgICAgICAgICAgIHQgPSAodCtlcil8MDtcblx0ICAgICAgICAgICAgICAgIGFyID0gZXI7XG5cdCAgICAgICAgICAgICAgICBlciA9IGRyO1xuXHQgICAgICAgICAgICAgICAgZHIgPSByb3RsKGNyLCAxMCk7XG5cdCAgICAgICAgICAgICAgICBjciA9IGJyO1xuXHQgICAgICAgICAgICAgICAgYnIgPSB0O1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgIC8vIEludGVybWVkaWF0ZSBoYXNoIHZhbHVlXG5cdCAgICAgICAgICAgIHQgICAgPSAoSFsxXSArIGNsICsgZHIpfDA7XG5cdCAgICAgICAgICAgIEhbMV0gPSAoSFsyXSArIGRsICsgZXIpfDA7XG5cdCAgICAgICAgICAgIEhbMl0gPSAoSFszXSArIGVsICsgYXIpfDA7XG5cdCAgICAgICAgICAgIEhbM10gPSAoSFs0XSArIGFsICsgYnIpfDA7XG5cdCAgICAgICAgICAgIEhbNF0gPSAoSFswXSArIGJsICsgY3IpfDA7XG5cdCAgICAgICAgICAgIEhbMF0gPSAgdDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvRmluYWxpemU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkYXRhID0gdGhpcy5fZGF0YTtcblx0ICAgICAgICAgICAgdmFyIGRhdGFXb3JkcyA9IGRhdGEud29yZHM7XG5cblx0ICAgICAgICAgICAgdmFyIG5CaXRzVG90YWwgPSB0aGlzLl9uRGF0YUJ5dGVzICogODtcblx0ICAgICAgICAgICAgdmFyIG5CaXRzTGVmdCA9IGRhdGEuc2lnQnl0ZXMgKiA4O1xuXG5cdCAgICAgICAgICAgIC8vIEFkZCBwYWRkaW5nXG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1tuQml0c0xlZnQgPj4+IDVdIHw9IDB4ODAgPDwgKDI0IC0gbkJpdHNMZWZ0ICUgMzIpO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKCgobkJpdHNMZWZ0ICsgNjQpID4+PiA5KSA8PCA0KSArIDE0XSA9IChcblx0ICAgICAgICAgICAgICAgICgoKG5CaXRzVG90YWwgPDwgOCkgIHwgKG5CaXRzVG90YWwgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8XG5cdCAgICAgICAgICAgICAgICAoKChuQml0c1RvdGFsIDw8IDI0KSB8IChuQml0c1RvdGFsID4+PiA4KSkgICYgMHhmZjAwZmYwMClcblx0ICAgICAgICAgICAgKTtcblx0ICAgICAgICAgICAgZGF0YS5zaWdCeXRlcyA9IChkYXRhV29yZHMubGVuZ3RoICsgMSkgKiA0O1xuXG5cdCAgICAgICAgICAgIC8vIEhhc2ggZmluYWwgYmxvY2tzXG5cdCAgICAgICAgICAgIHRoaXMuX3Byb2Nlc3MoKTtcblxuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGhhc2ggPSB0aGlzLl9oYXNoO1xuXHQgICAgICAgICAgICB2YXIgSCA9IGhhc2gud29yZHM7XG5cblx0ICAgICAgICAgICAgLy8gU3dhcCBlbmRpYW5cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA1OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgICAgICB2YXIgSF9pID0gSFtpXTtcblxuXHQgICAgICAgICAgICAgICAgLy8gU3dhcFxuXHQgICAgICAgICAgICAgICAgSFtpXSA9ICgoKEhfaSA8PCA4KSAgfCAoSF9pID4+PiAyNCkpICYgMHgwMGZmMDBmZikgfFxuXHQgICAgICAgICAgICAgICAgICAgICAgICgoKEhfaSA8PCAyNCkgfCAoSF9pID4+PiA4KSkgICYgMHhmZjAwZmYwMCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBSZXR1cm4gZmluYWwgY29tcHV0ZWQgaGFzaFxuXHQgICAgICAgICAgICByZXR1cm4gaGFzaDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgY2xvbmU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdmFyIGNsb25lID0gSGFzaGVyLmNsb25lLmNhbGwodGhpcyk7XG5cdCAgICAgICAgICAgIGNsb25lLl9oYXNoID0gdGhpcy5faGFzaC5jbG9uZSgpO1xuXG5cdCAgICAgICAgICAgIHJldHVybiBjbG9uZTtcblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXG5cdCAgICBmdW5jdGlvbiBmMSh4LCB5LCB6KSB7XG5cdCAgICAgICAgcmV0dXJuICgoeCkgXiAoeSkgXiAoeikpO1xuXG5cdCAgICB9XG5cblx0ICAgIGZ1bmN0aW9uIGYyKHgsIHksIHopIHtcblx0ICAgICAgICByZXR1cm4gKCgoeCkmKHkpKSB8ICgofngpJih6KSkpO1xuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiBmMyh4LCB5LCB6KSB7XG5cdCAgICAgICAgcmV0dXJuICgoKHgpIHwgKH4oeSkpKSBeICh6KSk7XG5cdCAgICB9XG5cblx0ICAgIGZ1bmN0aW9uIGY0KHgsIHksIHopIHtcblx0ICAgICAgICByZXR1cm4gKCgoeCkgJiAoeikpIHwgKCh5KSYofih6KSkpKTtcblx0ICAgIH1cblxuXHQgICAgZnVuY3Rpb24gZjUoeCwgeSwgeikge1xuXHQgICAgICAgIHJldHVybiAoKHgpIF4gKCh5KSB8KH4oeikpKSk7XG5cblx0ICAgIH1cblxuXHQgICAgZnVuY3Rpb24gcm90bCh4LG4pIHtcblx0ICAgICAgICByZXR1cm4gKHg8PG4pIHwgKHg+Pj4oMzItbikpO1xuXHQgICAgfVxuXG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIGhhc2hlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5SSVBFTUQxNjAoJ21lc3NhZ2UnKTtcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlJJUEVNRDE2MCh3b3JkQXJyYXkpO1xuXHQgICAgICovXG5cdCAgICBDLlJJUEVNRDE2MCA9IEhhc2hlci5fY3JlYXRlSGVscGVyKFJJUEVNRDE2MCk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIEhNQUMncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBrZXkgVGhlIHNlY3JldCBrZXkuXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgSE1BQy5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhtYWMgPSBDcnlwdG9KUy5IbWFjUklQRU1EMTYwKG1lc3NhZ2UsIGtleSk7XG5cdCAgICAgKi9cblx0ICAgIEMuSG1hY1JJUEVNRDE2MCA9IEhhc2hlci5fY3JlYXRlSG1hY0hlbHBlcihSSVBFTUQxNjApO1xuXHR9KE1hdGgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5SSVBFTUQxNjA7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5KSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgSGFzaGVyID0gQ19saWIuSGFzaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gUmV1c2FibGUgb2JqZWN0XG5cdCAgICB2YXIgVyA9IFtdO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNIQS0xIGhhc2ggYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgU0hBMSA9IENfYWxnby5TSEExID0gSGFzaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgX2RvUmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdGhpcy5faGFzaCA9IG5ldyBXb3JkQXJyYXkuaW5pdChbXG5cdCAgICAgICAgICAgICAgICAweDY3NDUyMzAxLCAweGVmY2RhYjg5LFxuXHQgICAgICAgICAgICAgICAgMHg5OGJhZGNmZSwgMHgxMDMyNTQ3Nixcblx0ICAgICAgICAgICAgICAgIDB4YzNkMmUxZjBcblx0ICAgICAgICAgICAgXSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb1Byb2Nlc3NCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dFxuXHQgICAgICAgICAgICB2YXIgSCA9IHRoaXMuX2hhc2gud29yZHM7XG5cblx0ICAgICAgICAgICAgLy8gV29ya2luZyB2YXJpYWJsZXNcblx0ICAgICAgICAgICAgdmFyIGEgPSBIWzBdO1xuXHQgICAgICAgICAgICB2YXIgYiA9IEhbMV07XG5cdCAgICAgICAgICAgIHZhciBjID0gSFsyXTtcblx0ICAgICAgICAgICAgdmFyIGQgPSBIWzNdO1xuXHQgICAgICAgICAgICB2YXIgZSA9IEhbNF07XG5cblx0ICAgICAgICAgICAgLy8gQ29tcHV0YXRpb25cblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCA4MDsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICBpZiAoaSA8IDE2KSB7XG5cdCAgICAgICAgICAgICAgICAgICAgV1tpXSA9IE1bb2Zmc2V0ICsgaV0gfCAwO1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIHtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgbiA9IFdbaSAtIDNdIF4gV1tpIC0gOF0gXiBXW2kgLSAxNF0gXiBXW2kgLSAxNl07XG5cdCAgICAgICAgICAgICAgICAgICAgV1tpXSA9IChuIDw8IDEpIHwgKG4gPj4+IDMxKTtcblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgdmFyIHQgPSAoKGEgPDwgNSkgfCAoYSA+Pj4gMjcpKSArIGUgKyBXW2ldO1xuXHQgICAgICAgICAgICAgICAgaWYgKGkgPCAyMCkge1xuXHQgICAgICAgICAgICAgICAgICAgIHQgKz0gKChiICYgYykgfCAofmIgJiBkKSkgKyAweDVhODI3OTk5O1xuXHQgICAgICAgICAgICAgICAgfSBlbHNlIGlmIChpIDwgNDApIHtcblx0ICAgICAgICAgICAgICAgICAgICB0ICs9IChiIF4gYyBeIGQpICsgMHg2ZWQ5ZWJhMTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSBpZiAoaSA8IDYwKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdCArPSAoKGIgJiBjKSB8IChiICYgZCkgfCAoYyAmIGQpKSAtIDB4NzBlNDQzMjQ7XG5cdCAgICAgICAgICAgICAgICB9IGVsc2UgLyogaWYgKGkgPCA4MCkgKi8ge1xuXHQgICAgICAgICAgICAgICAgICAgIHQgKz0gKGIgXiBjIF4gZCkgLSAweDM1OWQzZTJhO1xuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICBlID0gZDtcblx0ICAgICAgICAgICAgICAgIGQgPSBjO1xuXHQgICAgICAgICAgICAgICAgYyA9IChiIDw8IDMwKSB8IChiID4+PiAyKTtcblx0ICAgICAgICAgICAgICAgIGIgPSBhO1xuXHQgICAgICAgICAgICAgICAgYSA9IHQ7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBJbnRlcm1lZGlhdGUgaGFzaCB2YWx1ZVxuXHQgICAgICAgICAgICBIWzBdID0gKEhbMF0gKyBhKSB8IDA7XG5cdCAgICAgICAgICAgIEhbMV0gPSAoSFsxXSArIGIpIHwgMDtcblx0ICAgICAgICAgICAgSFsyXSA9IChIWzJdICsgYykgfCAwO1xuXHQgICAgICAgICAgICBIWzNdID0gKEhbM10gKyBkKSB8IDA7XG5cdCAgICAgICAgICAgIEhbNF0gPSAoSFs0XSArIGUpIHwgMDtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvRmluYWxpemU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgIHZhciBkYXRhID0gdGhpcy5fZGF0YTtcblx0ICAgICAgICAgICAgdmFyIGRhdGFXb3JkcyA9IGRhdGEud29yZHM7XG5cblx0ICAgICAgICAgICAgdmFyIG5CaXRzVG90YWwgPSB0aGlzLl9uRGF0YUJ5dGVzICogODtcblx0ICAgICAgICAgICAgdmFyIG5CaXRzTGVmdCA9IGRhdGEuc2lnQnl0ZXMgKiA4O1xuXG5cdCAgICAgICAgICAgIC8vIEFkZCBwYWRkaW5nXG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1tuQml0c0xlZnQgPj4+IDVdIHw9IDB4ODAgPDwgKDI0IC0gbkJpdHNMZWZ0ICUgMzIpO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKCgobkJpdHNMZWZ0ICsgNjQpID4+PiA5KSA8PCA0KSArIDE0XSA9IE1hdGguZmxvb3IobkJpdHNUb3RhbCAvIDB4MTAwMDAwMDAwKTtcblx0ICAgICAgICAgICAgZGF0YVdvcmRzWygoKG5CaXRzTGVmdCArIDY0KSA+Pj4gOSkgPDwgNCkgKyAxNV0gPSBuQml0c1RvdGFsO1xuXHQgICAgICAgICAgICBkYXRhLnNpZ0J5dGVzID0gZGF0YVdvcmRzLmxlbmd0aCAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gSGFzaCBmaW5hbCBibG9ja3Ncblx0ICAgICAgICAgICAgdGhpcy5fcHJvY2VzcygpO1xuXG5cdCAgICAgICAgICAgIC8vIFJldHVybiBmaW5hbCBjb21wdXRlZCBoYXNoXG5cdCAgICAgICAgICAgIHJldHVybiB0aGlzLl9oYXNoO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBIYXNoZXIuY2xvbmUuY2FsbCh0aGlzKTtcblx0ICAgICAgICAgICAgY2xvbmUuX2hhc2ggPSB0aGlzLl9oYXNoLmNsb25lKCk7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGNsb25lO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBoYXNoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBMSgnbWVzc2FnZScpO1xuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBMSh3b3JkQXJyYXkpO1xuXHQgICAgICovXG5cdCAgICBDLlNIQTEgPSBIYXNoZXIuX2NyZWF0ZUhlbHBlcihTSEExKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgSE1BQydzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IGtleSBUaGUgc2VjcmV0IGtleS5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBITUFDLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaG1hYyA9IENyeXB0b0pTLkhtYWNTSEExKG1lc3NhZ2UsIGtleSk7XG5cdCAgICAgKi9cblx0ICAgIEMuSG1hY1NIQTEgPSBIYXNoZXIuX2NyZWF0ZUhtYWNIZWxwZXIoU0hBMSk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuU0hBMTtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9zaGEyNTZcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vc2hhMjU2XCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5O1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblx0ICAgIHZhciBTSEEyNTYgPSBDX2FsZ28uU0hBMjU2O1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNIQS0yMjQgaGFzaCBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBTSEEyMjQgPSBDX2FsZ28uU0hBMjI0ID0gU0hBMjU2LmV4dGVuZCh7XG5cdCAgICAgICAgX2RvUmVzZXQ6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdGhpcy5faGFzaCA9IG5ldyBXb3JkQXJyYXkuaW5pdChbXG5cdCAgICAgICAgICAgICAgICAweGMxMDU5ZWQ4LCAweDM2N2NkNTA3LCAweDMwNzBkZDE3LCAweGY3MGU1OTM5LFxuXHQgICAgICAgICAgICAgICAgMHhmZmMwMGIzMSwgMHg2ODU4MTUxMSwgMHg2NGY5OGZhNywgMHhiZWZhNGZhNFxuXHQgICAgICAgICAgICBdKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvRmluYWxpemU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdmFyIGhhc2ggPSBTSEEyNTYuX2RvRmluYWxpemUuY2FsbCh0aGlzKTtcblxuXHQgICAgICAgICAgICBoYXNoLnNpZ0J5dGVzIC09IDQ7XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGhhc2g7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIGhhc2hlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5TSEEyMjQoJ21lc3NhZ2UnKTtcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlNIQTIyNCh3b3JkQXJyYXkpO1xuXHQgICAgICovXG5cdCAgICBDLlNIQTIyNCA9IFNIQTI1Ni5fY3JlYXRlSGVscGVyKFNIQTIyNCk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIEhNQUMncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBrZXkgVGhlIHNlY3JldCBrZXkuXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgSE1BQy5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhtYWMgPSBDcnlwdG9KUy5IbWFjU0hBMjI0KG1lc3NhZ2UsIGtleSk7XG5cdCAgICAgKi9cblx0ICAgIEMuSG1hY1NIQTIyNCA9IFNIQTI1Ni5fY3JlYXRlSG1hY0hlbHBlcihTSEEyMjQpO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLlNIQTIyNDtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnkpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiXSwgZmFjdG9yeSk7XG5cdH1cblx0ZWxzZSB7XG5cdFx0Ly8gR2xvYmFsIChicm93c2VyKVxuXHRcdGZhY3Rvcnkocm9vdC5DcnlwdG9KUyk7XG5cdH1cbn0odGhpcywgZnVuY3Rpb24gKENyeXB0b0pTKSB7XG5cblx0KGZ1bmN0aW9uIChNYXRoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ19saWIgPSBDLmxpYjtcblx0ICAgIHZhciBXb3JkQXJyYXkgPSBDX2xpYi5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgSGFzaGVyID0gQ19saWIuSGFzaGVyO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gSW5pdGlhbGl6YXRpb24gYW5kIHJvdW5kIGNvbnN0YW50cyB0YWJsZXNcblx0ICAgIHZhciBIID0gW107XG5cdCAgICB2YXIgSyA9IFtdO1xuXG5cdCAgICAvLyBDb21wdXRlIGNvbnN0YW50c1xuXHQgICAgKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICBmdW5jdGlvbiBpc1ByaW1lKG4pIHtcblx0ICAgICAgICAgICAgdmFyIHNxcnROID0gTWF0aC5zcXJ0KG4pO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBmYWN0b3IgPSAyOyBmYWN0b3IgPD0gc3FydE47IGZhY3RvcisrKSB7XG5cdCAgICAgICAgICAgICAgICBpZiAoIShuICUgZmFjdG9yKSkge1xuXHQgICAgICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIHJldHVybiB0cnVlO1xuXHQgICAgICAgIH1cblxuXHQgICAgICAgIGZ1bmN0aW9uIGdldEZyYWN0aW9uYWxCaXRzKG4pIHtcblx0ICAgICAgICAgICAgcmV0dXJuICgobiAtIChuIHwgMCkpICogMHgxMDAwMDAwMDApIHwgMDtcblx0ICAgICAgICB9XG5cblx0ICAgICAgICB2YXIgbiA9IDI7XG5cdCAgICAgICAgdmFyIG5QcmltZSA9IDA7XG5cdCAgICAgICAgd2hpbGUgKG5QcmltZSA8IDY0KSB7XG5cdCAgICAgICAgICAgIGlmIChpc1ByaW1lKG4pKSB7XG5cdCAgICAgICAgICAgICAgICBpZiAoblByaW1lIDwgOCkge1xuXHQgICAgICAgICAgICAgICAgICAgIEhbblByaW1lXSA9IGdldEZyYWN0aW9uYWxCaXRzKE1hdGgucG93KG4sIDEgLyAyKSk7XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgICAgICBLW25QcmltZV0gPSBnZXRGcmFjdGlvbmFsQml0cyhNYXRoLnBvdyhuLCAxIC8gMykpO1xuXG5cdCAgICAgICAgICAgICAgICBuUHJpbWUrKztcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIG4rKztcblx0ICAgICAgICB9XG5cdCAgICB9KCkpO1xuXG5cdCAgICAvLyBSZXVzYWJsZSBvYmplY3Rcblx0ICAgIHZhciBXID0gW107XG5cblx0ICAgIC8qKlxuXHQgICAgICogU0hBLTI1NiBoYXNoIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFNIQTI1NiA9IENfYWxnby5TSEEyNTYgPSBIYXNoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB0aGlzLl9oYXNoID0gbmV3IFdvcmRBcnJheS5pbml0KEguc2xpY2UoMCkpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9Qcm9jZXNzQmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgdmFyIEggPSB0aGlzLl9oYXNoLndvcmRzO1xuXG5cdCAgICAgICAgICAgIC8vIFdvcmtpbmcgdmFyaWFibGVzXG5cdCAgICAgICAgICAgIHZhciBhID0gSFswXTtcblx0ICAgICAgICAgICAgdmFyIGIgPSBIWzFdO1xuXHQgICAgICAgICAgICB2YXIgYyA9IEhbMl07XG5cdCAgICAgICAgICAgIHZhciBkID0gSFszXTtcblx0ICAgICAgICAgICAgdmFyIGUgPSBIWzRdO1xuXHQgICAgICAgICAgICB2YXIgZiA9IEhbNV07XG5cdCAgICAgICAgICAgIHZhciBnID0gSFs2XTtcblx0ICAgICAgICAgICAgdmFyIGggPSBIWzddO1xuXG5cdCAgICAgICAgICAgIC8vIENvbXB1dGF0aW9uXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgNjQ7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgaWYgKGkgPCAxNikge1xuXHQgICAgICAgICAgICAgICAgICAgIFdbaV0gPSBNW29mZnNldCArIGldIHwgMDtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMHggPSBXW2kgLSAxNV07XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMCAgPSAoKGdhbW1hMHggPDwgMjUpIHwgKGdhbW1hMHggPj4+IDcpKSAgXlxuXHQgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKChnYW1tYTB4IDw8IDE0KSB8IChnYW1tYTB4ID4+PiAxOCkpIF5cblx0ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAoZ2FtbWEweCA+Pj4gMyk7XG5cblx0ICAgICAgICAgICAgICAgICAgICB2YXIgZ2FtbWExeCA9IFdbaSAtIDJdO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTEgID0gKChnYW1tYTF4IDw8IDE1KSB8IChnYW1tYTF4ID4+PiAxNykpIF5cblx0ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICgoZ2FtbWExeCA8PCAxMykgfCAoZ2FtbWExeCA+Pj4gMTkpKSBeXG5cdCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgKGdhbW1hMXggPj4+IDEwKTtcblxuXHQgICAgICAgICAgICAgICAgICAgIFdbaV0gPSBnYW1tYTAgKyBXW2kgLSA3XSArIGdhbW1hMSArIFdbaSAtIDE2XTtcblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgdmFyIGNoICA9IChlICYgZikgXiAofmUgJiBnKTtcblx0ICAgICAgICAgICAgICAgIHZhciBtYWogPSAoYSAmIGIpIF4gKGEgJiBjKSBeIChiICYgYyk7XG5cblx0ICAgICAgICAgICAgICAgIHZhciBzaWdtYTAgPSAoKGEgPDwgMzApIHwgKGEgPj4+IDIpKSBeICgoYSA8PCAxOSkgfCAoYSA+Pj4gMTMpKSBeICgoYSA8PCAxMCkgfCAoYSA+Pj4gMjIpKTtcblx0ICAgICAgICAgICAgICAgIHZhciBzaWdtYTEgPSAoKGUgPDwgMjYpIHwgKGUgPj4+IDYpKSBeICgoZSA8PCAyMSkgfCAoZSA+Pj4gMTEpKSBeICgoZSA8PCA3KSAgfCAoZSA+Pj4gMjUpKTtcblxuXHQgICAgICAgICAgICAgICAgdmFyIHQxID0gaCArIHNpZ21hMSArIGNoICsgS1tpXSArIFdbaV07XG5cdCAgICAgICAgICAgICAgICB2YXIgdDIgPSBzaWdtYTAgKyBtYWo7XG5cblx0ICAgICAgICAgICAgICAgIGggPSBnO1xuXHQgICAgICAgICAgICAgICAgZyA9IGY7XG5cdCAgICAgICAgICAgICAgICBmID0gZTtcblx0ICAgICAgICAgICAgICAgIGUgPSAoZCArIHQxKSB8IDA7XG5cdCAgICAgICAgICAgICAgICBkID0gYztcblx0ICAgICAgICAgICAgICAgIGMgPSBiO1xuXHQgICAgICAgICAgICAgICAgYiA9IGE7XG5cdCAgICAgICAgICAgICAgICBhID0gKHQxICsgdDIpIHwgMDtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEludGVybWVkaWF0ZSBoYXNoIHZhbHVlXG5cdCAgICAgICAgICAgIEhbMF0gPSAoSFswXSArIGEpIHwgMDtcblx0ICAgICAgICAgICAgSFsxXSA9IChIWzFdICsgYikgfCAwO1xuXHQgICAgICAgICAgICBIWzJdID0gKEhbMl0gKyBjKSB8IDA7XG5cdCAgICAgICAgICAgIEhbM10gPSAoSFszXSArIGQpIHwgMDtcblx0ICAgICAgICAgICAgSFs0XSA9IChIWzRdICsgZSkgfCAwO1xuXHQgICAgICAgICAgICBIWzVdID0gKEhbNV0gKyBmKSB8IDA7XG5cdCAgICAgICAgICAgIEhbNl0gPSAoSFs2XSArIGcpIHwgMDtcblx0ICAgICAgICAgICAgSFs3XSA9IChIWzddICsgaCkgfCAwO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9GaW5hbGl6ZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGRhdGEgPSB0aGlzLl9kYXRhO1xuXHQgICAgICAgICAgICB2YXIgZGF0YVdvcmRzID0gZGF0YS53b3JkcztcblxuXHQgICAgICAgICAgICB2YXIgbkJpdHNUb3RhbCA9IHRoaXMuX25EYXRhQnl0ZXMgKiA4O1xuXHQgICAgICAgICAgICB2YXIgbkJpdHNMZWZ0ID0gZGF0YS5zaWdCeXRlcyAqIDg7XG5cblx0ICAgICAgICAgICAgLy8gQWRkIHBhZGRpbmdcblx0ICAgICAgICAgICAgZGF0YVdvcmRzW25CaXRzTGVmdCA+Pj4gNV0gfD0gMHg4MCA8PCAoMjQgLSBuQml0c0xlZnQgJSAzMik7XG5cdCAgICAgICAgICAgIGRhdGFXb3Jkc1soKChuQml0c0xlZnQgKyA2NCkgPj4+IDkpIDw8IDQpICsgMTRdID0gTWF0aC5mbG9vcihuQml0c1RvdGFsIC8gMHgxMDAwMDAwMDApO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKCgobkJpdHNMZWZ0ICsgNjQpID4+PiA5KSA8PCA0KSArIDE1XSA9IG5CaXRzVG90YWw7XG5cdCAgICAgICAgICAgIGRhdGEuc2lnQnl0ZXMgPSBkYXRhV29yZHMubGVuZ3RoICogNDtcblxuXHQgICAgICAgICAgICAvLyBIYXNoIGZpbmFsIGJsb2Nrc1xuXHQgICAgICAgICAgICB0aGlzLl9wcm9jZXNzKCk7XG5cblx0ICAgICAgICAgICAgLy8gUmV0dXJuIGZpbmFsIGNvbXB1dGVkIGhhc2hcblx0ICAgICAgICAgICAgcmV0dXJuIHRoaXMuX2hhc2g7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGNsb25lOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHZhciBjbG9uZSA9IEhhc2hlci5jbG9uZS5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICBjbG9uZS5faGFzaCA9IHRoaXMuX2hhc2guY2xvbmUoKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gY2xvbmU7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIGhhc2hlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5TSEEyNTYoJ21lc3NhZ2UnKTtcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlNIQTI1Nih3b3JkQXJyYXkpO1xuXHQgICAgICovXG5cdCAgICBDLlNIQTI1NiA9IEhhc2hlci5fY3JlYXRlSGVscGVyKFNIQTI1Nik7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIEhNQUMncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBrZXkgVGhlIHNlY3JldCBrZXkuXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgSE1BQy5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhtYWMgPSBDcnlwdG9KUy5IbWFjU0hBMjU2KG1lc3NhZ2UsIGtleSk7XG5cdCAgICAgKi9cblx0ICAgIEMuSG1hY1NIQTI1NiA9IEhhc2hlci5fY3JlYXRlSG1hY0hlbHBlcihTSEEyNTYpO1xuXHR9KE1hdGgpKTtcblxuXG5cdHJldHVybiBDcnlwdG9KUy5TSEEyNTY7XG5cbn0pKTsiLCI7KGZ1bmN0aW9uIChyb290LCBmYWN0b3J5LCB1bmRlZikge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSwgcmVxdWlyZShcIi4veDY0LWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4veDY0LWNvcmVcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoTWF0aCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5O1xuXHQgICAgdmFyIEhhc2hlciA9IENfbGliLkhhc2hlcjtcblx0ICAgIHZhciBDX3g2NCA9IEMueDY0O1xuXHQgICAgdmFyIFg2NFdvcmQgPSBDX3g2NC5Xb3JkO1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgLy8gQ29uc3RhbnRzIHRhYmxlc1xuXHQgICAgdmFyIFJIT19PRkZTRVRTID0gW107XG5cdCAgICB2YXIgUElfSU5ERVhFUyAgPSBbXTtcblx0ICAgIHZhciBST1VORF9DT05TVEFOVFMgPSBbXTtcblxuXHQgICAgLy8gQ29tcHV0ZSBDb25zdGFudHNcblx0ICAgIChmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgLy8gQ29tcHV0ZSByaG8gb2Zmc2V0IGNvbnN0YW50c1xuXHQgICAgICAgIHZhciB4ID0gMSwgeSA9IDA7XG5cdCAgICAgICAgZm9yICh2YXIgdCA9IDA7IHQgPCAyNDsgdCsrKSB7XG5cdCAgICAgICAgICAgIFJIT19PRkZTRVRTW3ggKyA1ICogeV0gPSAoKHQgKyAxKSAqICh0ICsgMikgLyAyKSAlIDY0O1xuXG5cdCAgICAgICAgICAgIHZhciBuZXdYID0geSAlIDU7XG5cdCAgICAgICAgICAgIHZhciBuZXdZID0gKDIgKiB4ICsgMyAqIHkpICUgNTtcblx0ICAgICAgICAgICAgeCA9IG5ld1g7XG5cdCAgICAgICAgICAgIHkgPSBuZXdZO1xuXHQgICAgICAgIH1cblxuXHQgICAgICAgIC8vIENvbXB1dGUgcGkgaW5kZXggY29uc3RhbnRzXG5cdCAgICAgICAgZm9yICh2YXIgeCA9IDA7IHggPCA1OyB4KyspIHtcblx0ICAgICAgICAgICAgZm9yICh2YXIgeSA9IDA7IHkgPCA1OyB5KyspIHtcblx0ICAgICAgICAgICAgICAgIFBJX0lOREVYRVNbeCArIDUgKiB5XSA9IHkgKyAoKDIgKiB4ICsgMyAqIHkpICUgNSkgKiA1O1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLy8gQ29tcHV0ZSByb3VuZCBjb25zdGFudHNcblx0ICAgICAgICB2YXIgTEZTUiA9IDB4MDE7XG5cdCAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNDsgaSsrKSB7XG5cdCAgICAgICAgICAgIHZhciByb3VuZENvbnN0YW50TXN3ID0gMDtcblx0ICAgICAgICAgICAgdmFyIHJvdW5kQ29uc3RhbnRMc3cgPSAwO1xuXG5cdCAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgNzsgaisrKSB7XG5cdCAgICAgICAgICAgICAgICBpZiAoTEZTUiAmIDB4MDEpIHtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgYml0UG9zaXRpb24gPSAoMSA8PCBqKSAtIDE7XG5cdCAgICAgICAgICAgICAgICAgICAgaWYgKGJpdFBvc2l0aW9uIDwgMzIpIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgcm91bmRDb25zdGFudExzdyBePSAxIDw8IGJpdFBvc2l0aW9uO1xuXHQgICAgICAgICAgICAgICAgICAgIH0gZWxzZSAvKiBpZiAoYml0UG9zaXRpb24gPj0gMzIpICovIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgcm91bmRDb25zdGFudE1zdyBePSAxIDw8IChiaXRQb3NpdGlvbiAtIDMyKTtcblx0ICAgICAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIC8vIENvbXB1dGUgbmV4dCBMRlNSXG5cdCAgICAgICAgICAgICAgICBpZiAoTEZTUiAmIDB4ODApIHtcblx0ICAgICAgICAgICAgICAgICAgICAvLyBQcmltaXRpdmUgcG9seW5vbWlhbCBvdmVyIEdGKDIpOiB4XjggKyB4XjYgKyB4XjUgKyB4XjQgKyAxXG5cdCAgICAgICAgICAgICAgICAgICAgTEZTUiA9IChMRlNSIDw8IDEpIF4gMHg3MTtcblx0ICAgICAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICAgICAgTEZTUiA8PD0gMTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIFJPVU5EX0NPTlNUQU5UU1tpXSA9IFg2NFdvcmQuY3JlYXRlKHJvdW5kQ29uc3RhbnRNc3csIHJvdW5kQ29uc3RhbnRMc3cpO1xuXHQgICAgICAgIH1cblx0ICAgIH0oKSk7XG5cblx0ICAgIC8vIFJldXNhYmxlIG9iamVjdHMgZm9yIHRlbXBvcmFyeSB2YWx1ZXNcblx0ICAgIHZhciBUID0gW107XG5cdCAgICAoZnVuY3Rpb24gKCkge1xuXHQgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMjU7IGkrKykge1xuXHQgICAgICAgICAgICBUW2ldID0gWDY0V29yZC5jcmVhdGUoKTtcblx0ICAgICAgICB9XG5cdCAgICB9KCkpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNIQS0zIGhhc2ggYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgU0hBMyA9IENfYWxnby5TSEEzID0gSGFzaGVyLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQ29uZmlndXJhdGlvbiBvcHRpb25zLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHByb3BlcnR5IHtudW1iZXJ9IG91dHB1dExlbmd0aFxuXHQgICAgICAgICAqICAgVGhlIGRlc2lyZWQgbnVtYmVyIG9mIGJpdHMgaW4gdGhlIG91dHB1dCBoYXNoLlxuXHQgICAgICAgICAqICAgT25seSB2YWx1ZXMgcGVybWl0dGVkIGFyZTogMjI0LCAyNTYsIDM4NCwgNTEyLlxuXHQgICAgICAgICAqICAgRGVmYXVsdDogNTEyXG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2ZnOiBIYXNoZXIuY2ZnLmV4dGVuZCh7XG5cdCAgICAgICAgICAgIG91dHB1dExlbmd0aDogNTEyXG5cdCAgICAgICAgfSksXG5cblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgc3RhdGUgPSB0aGlzLl9zdGF0ZSA9IFtdXG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMjU7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgc3RhdGVbaV0gPSBuZXcgWDY0V29yZC5pbml0KCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICB0aGlzLmJsb2NrU2l6ZSA9ICgxNjAwIC0gMiAqIHRoaXMuY2ZnLm91dHB1dExlbmd0aCkgLyAzMjtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvUHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgc3RhdGUgPSB0aGlzLl9zdGF0ZTtcblx0ICAgICAgICAgICAgdmFyIG5CbG9ja1NpemVMYW5lcyA9IHRoaXMuYmxvY2tTaXplIC8gMjtcblxuXHQgICAgICAgICAgICAvLyBBYnNvcmJcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBuQmxvY2tTaXplTGFuZXM7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgICAgICB2YXIgTTJpICA9IE1bb2Zmc2V0ICsgMiAqIGldO1xuXHQgICAgICAgICAgICAgICAgdmFyIE0yaTEgPSBNW29mZnNldCArIDIgKiBpICsgMV07XG5cblx0ICAgICAgICAgICAgICAgIC8vIFN3YXAgZW5kaWFuXG5cdCAgICAgICAgICAgICAgICBNMmkgPSAoXG5cdCAgICAgICAgICAgICAgICAgICAgKCgoTTJpIDw8IDgpICB8IChNMmkgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8XG5cdCAgICAgICAgICAgICAgICAgICAgKCgoTTJpIDw8IDI0KSB8IChNMmkgPj4+IDgpKSAgJiAweGZmMDBmZjAwKVxuXHQgICAgICAgICAgICAgICAgKTtcblx0ICAgICAgICAgICAgICAgIE0yaTEgPSAoXG5cdCAgICAgICAgICAgICAgICAgICAgKCgoTTJpMSA8PCA4KSAgfCAoTTJpMSA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICAgICAoKChNMmkxIDw8IDI0KSB8IChNMmkxID4+PiA4KSkgICYgMHhmZjAwZmYwMClcblx0ICAgICAgICAgICAgICAgICk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIEFic29yYiBtZXNzYWdlIGludG8gc3RhdGVcblx0ICAgICAgICAgICAgICAgIHZhciBsYW5lID0gc3RhdGVbaV07XG5cdCAgICAgICAgICAgICAgICBsYW5lLmhpZ2ggXj0gTTJpMTtcblx0ICAgICAgICAgICAgICAgIGxhbmUubG93ICBePSBNMmk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBSb3VuZHNcblx0ICAgICAgICAgICAgZm9yICh2YXIgcm91bmQgPSAwOyByb3VuZCA8IDI0OyByb3VuZCsrKSB7XG5cdCAgICAgICAgICAgICAgICAvLyBUaGV0YVxuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgeCA9IDA7IHggPCA1OyB4KyspIHtcblx0ICAgICAgICAgICAgICAgICAgICAvLyBNaXggY29sdW1uIGxhbmVzXG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIHRNc3cgPSAwLCB0THN3ID0gMDtcblx0ICAgICAgICAgICAgICAgICAgICBmb3IgKHZhciB5ID0gMDsgeSA8IDU7IHkrKykge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB2YXIgbGFuZSA9IHN0YXRlW3ggKyA1ICogeV07XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHRNc3cgXj0gbGFuZS5oaWdoO1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB0THN3IF49IGxhbmUubG93O1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgICAgIC8vIFRlbXBvcmFyeSB2YWx1ZXNcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgVHggPSBUW3hdO1xuXHQgICAgICAgICAgICAgICAgICAgIFR4LmhpZ2ggPSB0TXN3O1xuXHQgICAgICAgICAgICAgICAgICAgIFR4LmxvdyAgPSB0THN3O1xuXHQgICAgICAgICAgICAgICAgfVxuXHQgICAgICAgICAgICAgICAgZm9yICh2YXIgeCA9IDA7IHggPCA1OyB4KyspIHtcblx0ICAgICAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgVHg0ID0gVFsoeCArIDQpICUgNV07XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFR4MSA9IFRbKHggKyAxKSAlIDVdO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBUeDFNc3cgPSBUeDEuaGlnaDtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgVHgxTHN3ID0gVHgxLmxvdztcblxuXHQgICAgICAgICAgICAgICAgICAgIC8vIE1peCBzdXJyb3VuZGluZyBjb2x1bW5zXG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIHRNc3cgPSBUeDQuaGlnaCBeICgoVHgxTXN3IDw8IDEpIHwgKFR4MUxzdyA+Pj4gMzEpKTtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgdExzdyA9IFR4NC5sb3cgIF4gKChUeDFMc3cgPDwgMSkgfCAoVHgxTXN3ID4+PiAzMSkpO1xuXHQgICAgICAgICAgICAgICAgICAgIGZvciAodmFyIHkgPSAwOyB5IDwgNTsgeSsrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHZhciBsYW5lID0gc3RhdGVbeCArIDUgKiB5XTtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgbGFuZS5oaWdoIF49IHRNc3c7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIGxhbmUubG93ICBePSB0THN3O1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgLy8gUmhvIFBpXG5cdCAgICAgICAgICAgICAgICBmb3IgKHZhciBsYW5lSW5kZXggPSAxOyBsYW5lSW5kZXggPCAyNTsgbGFuZUluZGV4KyspIHtcblx0ICAgICAgICAgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgbGFuZSA9IHN0YXRlW2xhbmVJbmRleF07XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGxhbmVNc3cgPSBsYW5lLmhpZ2g7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGxhbmVMc3cgPSBsYW5lLmxvdztcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgcmhvT2Zmc2V0ID0gUkhPX09GRlNFVFNbbGFuZUluZGV4XTtcblxuXHQgICAgICAgICAgICAgICAgICAgIC8vIFJvdGF0ZSBsYW5lc1xuXHQgICAgICAgICAgICAgICAgICAgIGlmIChyaG9PZmZzZXQgPCAzMikge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdE1zdyA9IChsYW5lTXN3IDw8IHJob09mZnNldCkgfCAobGFuZUxzdyA+Pj4gKDMyIC0gcmhvT2Zmc2V0KSk7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHZhciB0THN3ID0gKGxhbmVMc3cgPDwgcmhvT2Zmc2V0KSB8IChsYW5lTXN3ID4+PiAoMzIgLSByaG9PZmZzZXQpKTtcblx0ICAgICAgICAgICAgICAgICAgICB9IGVsc2UgLyogaWYgKHJob09mZnNldCA+PSAzMikgKi8ge1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdE1zdyA9IChsYW5lTHN3IDw8IChyaG9PZmZzZXQgLSAzMikpIHwgKGxhbmVNc3cgPj4+ICg2NCAtIHJob09mZnNldCkpO1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB2YXIgdExzdyA9IChsYW5lTXN3IDw8IChyaG9PZmZzZXQgLSAzMikpIHwgKGxhbmVMc3cgPj4+ICg2NCAtIHJob09mZnNldCkpO1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgICAgIC8vIFRyYW5zcG9zZSBsYW5lc1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBUUGlMYW5lID0gVFtQSV9JTkRFWEVTW2xhbmVJbmRleF1dO1xuXHQgICAgICAgICAgICAgICAgICAgIFRQaUxhbmUuaGlnaCA9IHRNc3c7XG5cdCAgICAgICAgICAgICAgICAgICAgVFBpTGFuZS5sb3cgID0gdExzdztcblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgLy8gUmhvIHBpIGF0IHggPSB5ID0gMFxuXHQgICAgICAgICAgICAgICAgdmFyIFQwID0gVFswXTtcblx0ICAgICAgICAgICAgICAgIHZhciBzdGF0ZTAgPSBzdGF0ZVswXTtcblx0ICAgICAgICAgICAgICAgIFQwLmhpZ2ggPSBzdGF0ZTAuaGlnaDtcblx0ICAgICAgICAgICAgICAgIFQwLmxvdyAgPSBzdGF0ZTAubG93O1xuXG5cdCAgICAgICAgICAgICAgICAvLyBDaGlcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIHggPSAwOyB4IDwgNTsgeCsrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgZm9yICh2YXIgeSA9IDA7IHkgPCA1OyB5KyspIHtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRzXG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHZhciBsYW5lSW5kZXggPSB4ICsgNSAqIHk7XG5cdCAgICAgICAgICAgICAgICAgICAgICAgIHZhciBsYW5lID0gc3RhdGVbbGFuZUluZGV4XTtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdmFyIFRMYW5lID0gVFtsYW5lSW5kZXhdO1xuXHQgICAgICAgICAgICAgICAgICAgICAgICB2YXIgVHgxTGFuZSA9IFRbKCh4ICsgMSkgJSA1KSArIDUgKiB5XTtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgdmFyIFR4MkxhbmUgPSBUWygoeCArIDIpICUgNSkgKyA1ICogeV07XG5cblx0ICAgICAgICAgICAgICAgICAgICAgICAgLy8gTWl4IHJvd3Ncblx0ICAgICAgICAgICAgICAgICAgICAgICAgbGFuZS5oaWdoID0gVExhbmUuaGlnaCBeICh+VHgxTGFuZS5oaWdoICYgVHgyTGFuZS5oaWdoKTtcblx0ICAgICAgICAgICAgICAgICAgICAgICAgbGFuZS5sb3cgID0gVExhbmUubG93ICBeICh+VHgxTGFuZS5sb3cgICYgVHgyTGFuZS5sb3cpO1xuXHQgICAgICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAgICAgLy8gSW90YVxuXHQgICAgICAgICAgICAgICAgdmFyIGxhbmUgPSBzdGF0ZVswXTtcblx0ICAgICAgICAgICAgICAgIHZhciByb3VuZENvbnN0YW50ID0gUk9VTkRfQ09OU1RBTlRTW3JvdW5kXTtcblx0ICAgICAgICAgICAgICAgIGxhbmUuaGlnaCBePSByb3VuZENvbnN0YW50LmhpZ2g7XG5cdCAgICAgICAgICAgICAgICBsYW5lLmxvdyAgXj0gcm91bmRDb25zdGFudC5sb3c7O1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0ZpbmFsaXplOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgZGF0YSA9IHRoaXMuX2RhdGE7XG5cdCAgICAgICAgICAgIHZhciBkYXRhV29yZHMgPSBkYXRhLndvcmRzO1xuXHQgICAgICAgICAgICB2YXIgbkJpdHNUb3RhbCA9IHRoaXMuX25EYXRhQnl0ZXMgKiA4O1xuXHQgICAgICAgICAgICB2YXIgbkJpdHNMZWZ0ID0gZGF0YS5zaWdCeXRlcyAqIDg7XG5cdCAgICAgICAgICAgIHZhciBibG9ja1NpemVCaXRzID0gdGhpcy5ibG9ja1NpemUgKiAzMjtcblxuXHQgICAgICAgICAgICAvLyBBZGQgcGFkZGluZ1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbbkJpdHNMZWZ0ID4+PiA1XSB8PSAweDEgPDwgKDI0IC0gbkJpdHNMZWZ0ICUgMzIpO1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbKChNYXRoLmNlaWwoKG5CaXRzTGVmdCArIDEpIC8gYmxvY2tTaXplQml0cykgKiBibG9ja1NpemVCaXRzKSA+Pj4gNSkgLSAxXSB8PSAweDgwO1xuXHQgICAgICAgICAgICBkYXRhLnNpZ0J5dGVzID0gZGF0YVdvcmRzLmxlbmd0aCAqIDQ7XG5cblx0ICAgICAgICAgICAgLy8gSGFzaCBmaW5hbCBibG9ja3Ncblx0ICAgICAgICAgICAgdGhpcy5fcHJvY2VzcygpO1xuXG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgc3RhdGUgPSB0aGlzLl9zdGF0ZTtcblx0ICAgICAgICAgICAgdmFyIG91dHB1dExlbmd0aEJ5dGVzID0gdGhpcy5jZmcub3V0cHV0TGVuZ3RoIC8gODtcblx0ICAgICAgICAgICAgdmFyIG91dHB1dExlbmd0aExhbmVzID0gb3V0cHV0TGVuZ3RoQnl0ZXMgLyA4O1xuXG5cdCAgICAgICAgICAgIC8vIFNxdWVlemVcblx0ICAgICAgICAgICAgdmFyIGhhc2hXb3JkcyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IG91dHB1dExlbmd0aExhbmVzOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgdmFyIGxhbmUgPSBzdGF0ZVtpXTtcblx0ICAgICAgICAgICAgICAgIHZhciBsYW5lTXN3ID0gbGFuZS5oaWdoO1xuXHQgICAgICAgICAgICAgICAgdmFyIGxhbmVMc3cgPSBsYW5lLmxvdztcblxuXHQgICAgICAgICAgICAgICAgLy8gU3dhcCBlbmRpYW5cblx0ICAgICAgICAgICAgICAgIGxhbmVNc3cgPSAoXG5cdCAgICAgICAgICAgICAgICAgICAgKCgobGFuZU1zdyA8PCA4KSAgfCAobGFuZU1zdyA+Pj4gMjQpKSAmIDB4MDBmZjAwZmYpIHxcblx0ICAgICAgICAgICAgICAgICAgICAoKChsYW5lTXN3IDw8IDI0KSB8IChsYW5lTXN3ID4+PiA4KSkgICYgMHhmZjAwZmYwMClcblx0ICAgICAgICAgICAgICAgICk7XG5cdCAgICAgICAgICAgICAgICBsYW5lTHN3ID0gKFxuXHQgICAgICAgICAgICAgICAgICAgICgoKGxhbmVMc3cgPDwgOCkgIHwgKGxhbmVMc3cgPj4+IDI0KSkgJiAweDAwZmYwMGZmKSB8XG5cdCAgICAgICAgICAgICAgICAgICAgKCgobGFuZUxzdyA8PCAyNCkgfCAobGFuZUxzdyA+Pj4gOCkpICAmIDB4ZmYwMGZmMDApXG5cdCAgICAgICAgICAgICAgICApO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBTcXVlZXplIHN0YXRlIHRvIHJldHJpZXZlIGhhc2hcblx0ICAgICAgICAgICAgICAgIGhhc2hXb3Jkcy5wdXNoKGxhbmVMc3cpO1xuXHQgICAgICAgICAgICAgICAgaGFzaFdvcmRzLnB1c2gobGFuZU1zdyk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBSZXR1cm4gZmluYWwgY29tcHV0ZWQgaGFzaFxuXHQgICAgICAgICAgICByZXR1cm4gbmV3IFdvcmRBcnJheS5pbml0KGhhc2hXb3Jkcywgb3V0cHV0TGVuZ3RoQnl0ZXMpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBjbG9uZTogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB2YXIgY2xvbmUgPSBIYXNoZXIuY2xvbmUuY2FsbCh0aGlzKTtcblxuXHQgICAgICAgICAgICB2YXIgc3RhdGUgPSBjbG9uZS5fc3RhdGUgPSB0aGlzLl9zdGF0ZS5zbGljZSgwKTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNTsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICBzdGF0ZVtpXSA9IHN0YXRlW2ldLmNsb25lKCk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICByZXR1cm4gY2xvbmU7XG5cdCAgICAgICAgfVxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIGhhc2hlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5TSEEzKCdtZXNzYWdlJyk7XG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5TSEEzKHdvcmRBcnJheSk7XG5cdCAgICAgKi9cblx0ICAgIEMuU0hBMyA9IEhhc2hlci5fY3JlYXRlSGVscGVyKFNIQTMpO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9uIHRvIHRoZSBITUFDJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30ga2V5IFRoZSBzZWNyZXQga2V5LlxuXHQgICAgICpcblx0ICAgICAqIEByZXR1cm4ge1dvcmRBcnJheX0gVGhlIEhNQUMuXG5cdCAgICAgKlxuXHQgICAgICogQHN0YXRpY1xuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBobWFjID0gQ3J5cHRvSlMuSG1hY1NIQTMobWVzc2FnZSwga2V5KTtcblx0ICAgICAqL1xuXHQgICAgQy5IbWFjU0hBMyA9IEhhc2hlci5fY3JlYXRlSG1hY0hlbHBlcihTSEEzKTtcblx0fShNYXRoKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuU0hBMztcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi94NjQtY29yZVwiKSwgcmVxdWlyZShcIi4vc2hhNTEyXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL3g2NC1jb3JlXCIsIFwiLi9zaGE1MTJcIl0sIGZhY3RvcnkpO1xuXHR9XG5cdGVsc2Uge1xuXHRcdC8vIEdsb2JhbCAoYnJvd3Nlcilcblx0XHRmYWN0b3J5KHJvb3QuQ3J5cHRvSlMpO1xuXHR9XG59KHRoaXMsIGZ1bmN0aW9uIChDcnlwdG9KUykge1xuXG5cdChmdW5jdGlvbiAoKSB7XG5cdCAgICAvLyBTaG9ydGN1dHNcblx0ICAgIHZhciBDID0gQ3J5cHRvSlM7XG5cdCAgICB2YXIgQ194NjQgPSBDLng2NDtcblx0ICAgIHZhciBYNjRXb3JkID0gQ194NjQuV29yZDtcblx0ICAgIHZhciBYNjRXb3JkQXJyYXkgPSBDX3g2NC5Xb3JkQXJyYXk7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXHQgICAgdmFyIFNIQTUxMiA9IENfYWxnby5TSEE1MTI7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU0hBLTM4NCBoYXNoIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIFNIQTM4NCA9IENfYWxnby5TSEEzODQgPSBTSEE1MTIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICB0aGlzLl9oYXNoID0gbmV3IFg2NFdvcmRBcnJheS5pbml0KFtcblx0ICAgICAgICAgICAgICAgIG5ldyBYNjRXb3JkLmluaXQoMHhjYmJiOWQ1ZCwgMHhjMTA1OWVkOCksIG5ldyBYNjRXb3JkLmluaXQoMHg2MjlhMjkyYSwgMHgzNjdjZDUwNyksXG5cdCAgICAgICAgICAgICAgICBuZXcgWDY0V29yZC5pbml0KDB4OTE1OTAxNWEsIDB4MzA3MGRkMTcpLCBuZXcgWDY0V29yZC5pbml0KDB4MTUyZmVjZDgsIDB4ZjcwZTU5MzkpLFxuXHQgICAgICAgICAgICAgICAgbmV3IFg2NFdvcmQuaW5pdCgweDY3MzMyNjY3LCAweGZmYzAwYjMxKSwgbmV3IFg2NFdvcmQuaW5pdCgweDhlYjQ0YTg3LCAweDY4NTgxNTExKSxcblx0ICAgICAgICAgICAgICAgIG5ldyBYNjRXb3JkLmluaXQoMHhkYjBjMmUwZCwgMHg2NGY5OGZhNyksIG5ldyBYNjRXb3JkLmluaXQoMHg0N2I1NDgxZCwgMHhiZWZhNGZhNClcblx0ICAgICAgICAgICAgXSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0ZpbmFsaXplOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHZhciBoYXNoID0gU0hBNTEyLl9kb0ZpbmFsaXplLmNhbGwodGhpcyk7XG5cblx0ICAgICAgICAgICAgaGFzaC5zaWdCeXRlcyAtPSAxNjtcblxuXHQgICAgICAgICAgICByZXR1cm4gaGFzaDtcblx0ICAgICAgICB9XG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgaGFzaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IG1lc3NhZ2UgVGhlIG1lc3NhZ2UgdG8gaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBoYXNoLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlNIQTM4NCgnbWVzc2FnZScpO1xuXHQgICAgICogICAgIHZhciBoYXNoID0gQ3J5cHRvSlMuU0hBMzg0KHdvcmRBcnJheSk7XG5cdCAgICAgKi9cblx0ICAgIEMuU0hBMzg0ID0gU0hBNTEyLl9jcmVhdGVIZWxwZXIoU0hBMzg0KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTaG9ydGN1dCBmdW5jdGlvbiB0byB0aGUgSE1BQydzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKiBAcGFyYW0ge1dvcmRBcnJheXxzdHJpbmd9IGtleSBUaGUgc2VjcmV0IGtleS5cblx0ICAgICAqXG5cdCAgICAgKiBAcmV0dXJuIHtXb3JkQXJyYXl9IFRoZSBITUFDLlxuXHQgICAgICpcblx0ICAgICAqIEBzdGF0aWNcblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgaG1hYyA9IENyeXB0b0pTLkhtYWNTSEEzODQobWVzc2FnZSwga2V5KTtcblx0ICAgICAqL1xuXHQgICAgQy5IbWFjU0hBMzg0ID0gU0hBNTEyLl9jcmVhdGVIbWFjSGVscGVyKFNIQTM4NCk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuU0hBMzg0O1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSwgdW5kZWYpIHtcblx0aWYgKHR5cGVvZiBleHBvcnRzID09PSBcIm9iamVjdFwiKSB7XG5cdFx0Ly8gQ29tbW9uSlNcblx0XHRtb2R1bGUuZXhwb3J0cyA9IGV4cG9ydHMgPSBmYWN0b3J5KHJlcXVpcmUoXCIuL2NvcmVcIiksIHJlcXVpcmUoXCIuL3g2NC1jb3JlXCIpKTtcblx0fVxuXHRlbHNlIGlmICh0eXBlb2YgZGVmaW5lID09PSBcImZ1bmN0aW9uXCIgJiYgZGVmaW5lLmFtZCkge1xuXHRcdC8vIEFNRFxuXHRcdGRlZmluZShbXCIuL2NvcmVcIiwgXCIuL3g2NC1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgSGFzaGVyID0gQ19saWIuSGFzaGVyO1xuXHQgICAgdmFyIENfeDY0ID0gQy54NjQ7XG5cdCAgICB2YXIgWDY0V29yZCA9IENfeDY0LldvcmQ7XG5cdCAgICB2YXIgWDY0V29yZEFycmF5ID0gQ194NjQuV29yZEFycmF5O1xuXHQgICAgdmFyIENfYWxnbyA9IEMuYWxnbztcblxuXHQgICAgZnVuY3Rpb24gWDY0V29yZF9jcmVhdGUoKSB7XG5cdCAgICAgICAgcmV0dXJuIFg2NFdvcmQuY3JlYXRlLmFwcGx5KFg2NFdvcmQsIGFyZ3VtZW50cyk7XG5cdCAgICB9XG5cblx0ICAgIC8vIENvbnN0YW50c1xuXHQgICAgdmFyIEsgPSBbXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg0MjhhMmY5OCwgMHhkNzI4YWUyMiksIFg2NFdvcmRfY3JlYXRlKDB4NzEzNzQ0OTEsIDB4MjNlZjY1Y2QpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4YjVjMGZiY2YsIDB4ZWM0ZDNiMmYpLCBYNjRXb3JkX2NyZWF0ZSgweGU5YjVkYmE1LCAweDgxODlkYmJjKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDM5NTZjMjViLCAweGYzNDhiNTM4KSwgWDY0V29yZF9jcmVhdGUoMHg1OWYxMTFmMSwgMHhiNjA1ZDAxOSksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg5MjNmODJhNCwgMHhhZjE5NGY5YiksIFg2NFdvcmRfY3JlYXRlKDB4YWIxYzVlZDUsIDB4ZGE2ZDgxMTgpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4ZDgwN2FhOTgsIDB4YTMwMzAyNDIpLCBYNjRXb3JkX2NyZWF0ZSgweDEyODM1YjAxLCAweDQ1NzA2ZmJlKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDI0MzE4NWJlLCAweDRlZTRiMjhjKSwgWDY0V29yZF9jcmVhdGUoMHg1NTBjN2RjMywgMHhkNWZmYjRlMiksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg3MmJlNWQ3NCwgMHhmMjdiODk2ZiksIFg2NFdvcmRfY3JlYXRlKDB4ODBkZWIxZmUsIDB4M2IxNjk2YjEpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4OWJkYzA2YTcsIDB4MjVjNzEyMzUpLCBYNjRXb3JkX2NyZWF0ZSgweGMxOWJmMTc0LCAweGNmNjkyNjk0KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweGU0OWI2OWMxLCAweDllZjE0YWQyKSwgWDY0V29yZF9jcmVhdGUoMHhlZmJlNDc4NiwgMHgzODRmMjVlMyksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHgwZmMxOWRjNiwgMHg4YjhjZDViNSksIFg2NFdvcmRfY3JlYXRlKDB4MjQwY2ExY2MsIDB4NzdhYzljNjUpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4MmRlOTJjNmYsIDB4NTkyYjAyNzUpLCBYNjRXb3JkX2NyZWF0ZSgweDRhNzQ4NGFhLCAweDZlYTZlNDgzKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDVjYjBhOWRjLCAweGJkNDFmYmQ0KSwgWDY0V29yZF9jcmVhdGUoMHg3NmY5ODhkYSwgMHg4MzExNTNiNSksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg5ODNlNTE1MiwgMHhlZTY2ZGZhYiksIFg2NFdvcmRfY3JlYXRlKDB4YTgzMWM2NmQsIDB4MmRiNDMyMTApLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4YjAwMzI3YzgsIDB4OThmYjIxM2YpLCBYNjRXb3JkX2NyZWF0ZSgweGJmNTk3ZmM3LCAweGJlZWYwZWU0KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweGM2ZTAwYmYzLCAweDNkYTg4ZmMyKSwgWDY0V29yZF9jcmVhdGUoMHhkNWE3OTE0NywgMHg5MzBhYTcyNSksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHgwNmNhNjM1MSwgMHhlMDAzODI2ZiksIFg2NFdvcmRfY3JlYXRlKDB4MTQyOTI5NjcsIDB4MGEwZTZlNzApLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4MjdiNzBhODUsIDB4NDZkMjJmZmMpLCBYNjRXb3JkX2NyZWF0ZSgweDJlMWIyMTM4LCAweDVjMjZjOTI2KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDRkMmM2ZGZjLCAweDVhYzQyYWVkKSwgWDY0V29yZF9jcmVhdGUoMHg1MzM4MGQxMywgMHg5ZDk1YjNkZiksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg2NTBhNzM1NCwgMHg4YmFmNjNkZSksIFg2NFdvcmRfY3JlYXRlKDB4NzY2YTBhYmIsIDB4M2M3N2IyYTgpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4ODFjMmM5MmUsIDB4NDdlZGFlZTYpLCBYNjRXb3JkX2NyZWF0ZSgweDkyNzIyYzg1LCAweDE0ODIzNTNiKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweGEyYmZlOGExLCAweDRjZjEwMzY0KSwgWDY0V29yZF9jcmVhdGUoMHhhODFhNjY0YiwgMHhiYzQyMzAwMSksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHhjMjRiOGI3MCwgMHhkMGY4OTc5MSksIFg2NFdvcmRfY3JlYXRlKDB4Yzc2YzUxYTMsIDB4MDY1NGJlMzApLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4ZDE5MmU4MTksIDB4ZDZlZjUyMTgpLCBYNjRXb3JkX2NyZWF0ZSgweGQ2OTkwNjI0LCAweDU1NjVhOTEwKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweGY0MGUzNTg1LCAweDU3NzEyMDJhKSwgWDY0V29yZF9jcmVhdGUoMHgxMDZhYTA3MCwgMHgzMmJiZDFiOCksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHgxOWE0YzExNiwgMHhiOGQyZDBjOCksIFg2NFdvcmRfY3JlYXRlKDB4MWUzNzZjMDgsIDB4NTE0MWFiNTMpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4Mjc0ODc3NGMsIDB4ZGY4ZWViOTkpLCBYNjRXb3JkX2NyZWF0ZSgweDM0YjBiY2I1LCAweGUxOWI0OGE4KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDM5MWMwY2IzLCAweGM1Yzk1YTYzKSwgWDY0V29yZF9jcmVhdGUoMHg0ZWQ4YWE0YSwgMHhlMzQxOGFjYiksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg1YjljY2E0ZiwgMHg3NzYzZTM3MyksIFg2NFdvcmRfY3JlYXRlKDB4NjgyZTZmZjMsIDB4ZDZiMmI4YTMpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4NzQ4ZjgyZWUsIDB4NWRlZmIyZmMpLCBYNjRXb3JkX2NyZWF0ZSgweDc4YTU2MzZmLCAweDQzMTcyZjYwKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDg0Yzg3ODE0LCAweGExZjBhYjcyKSwgWDY0V29yZF9jcmVhdGUoMHg4Y2M3MDIwOCwgMHgxYTY0MzllYyksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg5MGJlZmZmYSwgMHgyMzYzMWUyOCksIFg2NFdvcmRfY3JlYXRlKDB4YTQ1MDZjZWIsIDB4ZGU4MmJkZTkpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4YmVmOWEzZjcsIDB4YjJjNjc5MTUpLCBYNjRXb3JkX2NyZWF0ZSgweGM2NzE3OGYyLCAweGUzNzI1MzJiKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweGNhMjczZWNlLCAweGVhMjY2MTljKSwgWDY0V29yZF9jcmVhdGUoMHhkMTg2YjhjNywgMHgyMWMwYzIwNyksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHhlYWRhN2RkNiwgMHhjZGUwZWIxZSksIFg2NFdvcmRfY3JlYXRlKDB4ZjU3ZDRmN2YsIDB4ZWU2ZWQxNzgpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4MDZmMDY3YWEsIDB4NzIxNzZmYmEpLCBYNjRXb3JkX2NyZWF0ZSgweDBhNjM3ZGM1LCAweGEyYzg5OGE2KSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDExM2Y5ODA0LCAweGJlZjkwZGFlKSwgWDY0V29yZF9jcmVhdGUoMHgxYjcxMGIzNSwgMHgxMzFjNDcxYiksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHgyOGRiNzdmNSwgMHgyMzA0N2Q4NCksIFg2NFdvcmRfY3JlYXRlKDB4MzJjYWFiN2IsIDB4NDBjNzI0OTMpLFxuXHQgICAgICAgIFg2NFdvcmRfY3JlYXRlKDB4M2M5ZWJlMGEsIDB4MTVjOWJlYmMpLCBYNjRXb3JkX2NyZWF0ZSgweDQzMWQ2N2M0LCAweDljMTAwZDRjKSxcblx0ICAgICAgICBYNjRXb3JkX2NyZWF0ZSgweDRjYzVkNGJlLCAweGNiM2U0MmI2KSwgWDY0V29yZF9jcmVhdGUoMHg1OTdmMjk5YywgMHhmYzY1N2UyYSksXG5cdCAgICAgICAgWDY0V29yZF9jcmVhdGUoMHg1ZmNiNmZhYiwgMHgzYWQ2ZmFlYyksIFg2NFdvcmRfY3JlYXRlKDB4NmM0NDE5OGMsIDB4NGE0NzU4MTcpXG5cdCAgICBdO1xuXG5cdCAgICAvLyBSZXVzYWJsZSBvYmplY3RzXG5cdCAgICB2YXIgVyA9IFtdO1xuXHQgICAgKGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDgwOyBpKyspIHtcblx0ICAgICAgICAgICAgV1tpXSA9IFg2NFdvcmRfY3JlYXRlKCk7XG5cdCAgICAgICAgfVxuXHQgICAgfSgpKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBTSEEtNTEyIGhhc2ggYWxnb3JpdGhtLlxuXHQgICAgICovXG5cdCAgICB2YXIgU0hBNTEyID0gQ19hbGdvLlNIQTUxMiA9IEhhc2hlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHRoaXMuX2hhc2ggPSBuZXcgWDY0V29yZEFycmF5LmluaXQoW1xuXHQgICAgICAgICAgICAgICAgbmV3IFg2NFdvcmQuaW5pdCgweDZhMDllNjY3LCAweGYzYmNjOTA4KSwgbmV3IFg2NFdvcmQuaW5pdCgweGJiNjdhZTg1LCAweDg0Y2FhNzNiKSxcblx0ICAgICAgICAgICAgICAgIG5ldyBYNjRXb3JkLmluaXQoMHgzYzZlZjM3MiwgMHhmZTk0ZjgyYiksIG5ldyBYNjRXb3JkLmluaXQoMHhhNTRmZjUzYSwgMHg1ZjFkMzZmMSksXG5cdCAgICAgICAgICAgICAgICBuZXcgWDY0V29yZC5pbml0KDB4NTEwZTUyN2YsIDB4YWRlNjgyZDEpLCBuZXcgWDY0V29yZC5pbml0KDB4OWIwNTY4OGMsIDB4MmIzZTZjMWYpLFxuXHQgICAgICAgICAgICAgICAgbmV3IFg2NFdvcmQuaW5pdCgweDFmODNkOWFiLCAweGZiNDFiZDZiKSwgbmV3IFg2NFdvcmQuaW5pdCgweDViZTBjZDE5LCAweDEzN2UyMTc5KVxuXHQgICAgICAgICAgICBdKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgX2RvUHJvY2Vzc0Jsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgSCA9IHRoaXMuX2hhc2gud29yZHM7XG5cblx0ICAgICAgICAgICAgdmFyIEgwID0gSFswXTtcblx0ICAgICAgICAgICAgdmFyIEgxID0gSFsxXTtcblx0ICAgICAgICAgICAgdmFyIEgyID0gSFsyXTtcblx0ICAgICAgICAgICAgdmFyIEgzID0gSFszXTtcblx0ICAgICAgICAgICAgdmFyIEg0ID0gSFs0XTtcblx0ICAgICAgICAgICAgdmFyIEg1ID0gSFs1XTtcblx0ICAgICAgICAgICAgdmFyIEg2ID0gSFs2XTtcblx0ICAgICAgICAgICAgdmFyIEg3ID0gSFs3XTtcblxuXHQgICAgICAgICAgICB2YXIgSDBoID0gSDAuaGlnaDtcblx0ICAgICAgICAgICAgdmFyIEgwbCA9IEgwLmxvdztcblx0ICAgICAgICAgICAgdmFyIEgxaCA9IEgxLmhpZ2g7XG5cdCAgICAgICAgICAgIHZhciBIMWwgPSBIMS5sb3c7XG5cdCAgICAgICAgICAgIHZhciBIMmggPSBIMi5oaWdoO1xuXHQgICAgICAgICAgICB2YXIgSDJsID0gSDIubG93O1xuXHQgICAgICAgICAgICB2YXIgSDNoID0gSDMuaGlnaDtcblx0ICAgICAgICAgICAgdmFyIEgzbCA9IEgzLmxvdztcblx0ICAgICAgICAgICAgdmFyIEg0aCA9IEg0LmhpZ2g7XG5cdCAgICAgICAgICAgIHZhciBINGwgPSBINC5sb3c7XG5cdCAgICAgICAgICAgIHZhciBINWggPSBINS5oaWdoO1xuXHQgICAgICAgICAgICB2YXIgSDVsID0gSDUubG93O1xuXHQgICAgICAgICAgICB2YXIgSDZoID0gSDYuaGlnaDtcblx0ICAgICAgICAgICAgdmFyIEg2bCA9IEg2Lmxvdztcblx0ICAgICAgICAgICAgdmFyIEg3aCA9IEg3LmhpZ2g7XG5cdCAgICAgICAgICAgIHZhciBIN2wgPSBINy5sb3c7XG5cblx0ICAgICAgICAgICAgLy8gV29ya2luZyB2YXJpYWJsZXNcblx0ICAgICAgICAgICAgdmFyIGFoID0gSDBoO1xuXHQgICAgICAgICAgICB2YXIgYWwgPSBIMGw7XG5cdCAgICAgICAgICAgIHZhciBiaCA9IEgxaDtcblx0ICAgICAgICAgICAgdmFyIGJsID0gSDFsO1xuXHQgICAgICAgICAgICB2YXIgY2ggPSBIMmg7XG5cdCAgICAgICAgICAgIHZhciBjbCA9IEgybDtcblx0ICAgICAgICAgICAgdmFyIGRoID0gSDNoO1xuXHQgICAgICAgICAgICB2YXIgZGwgPSBIM2w7XG5cdCAgICAgICAgICAgIHZhciBlaCA9IEg0aDtcblx0ICAgICAgICAgICAgdmFyIGVsID0gSDRsO1xuXHQgICAgICAgICAgICB2YXIgZmggPSBINWg7XG5cdCAgICAgICAgICAgIHZhciBmbCA9IEg1bDtcblx0ICAgICAgICAgICAgdmFyIGdoID0gSDZoO1xuXHQgICAgICAgICAgICB2YXIgZ2wgPSBINmw7XG5cdCAgICAgICAgICAgIHZhciBoaCA9IEg3aDtcblx0ICAgICAgICAgICAgdmFyIGhsID0gSDdsO1xuXG5cdCAgICAgICAgICAgIC8vIFJvdW5kc1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDgwOyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0XG5cdCAgICAgICAgICAgICAgICB2YXIgV2kgPSBXW2ldO1xuXG5cdCAgICAgICAgICAgICAgICAvLyBFeHRlbmQgbWVzc2FnZVxuXHQgICAgICAgICAgICAgICAgaWYgKGkgPCAxNikge1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBXaWggPSBXaS5oaWdoID0gTVtvZmZzZXQgKyBpICogMl0gICAgIHwgMDtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgV2lsID0gV2kubG93ICA9IE1bb2Zmc2V0ICsgaSAqIDIgKyAxXSB8IDA7XG5cdCAgICAgICAgICAgICAgICB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgICAgIC8vIEdhbW1hMFxuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTB4ICA9IFdbaSAtIDE1XTtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgZ2FtbWEweGggPSBnYW1tYTB4LmhpZ2g7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMHhsID0gZ2FtbWEweC5sb3c7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIGdhbW1hMGggID0gKChnYW1tYTB4aCA+Pj4gMSkgfCAoZ2FtbWEweGwgPDwgMzEpKSBeICgoZ2FtbWEweGggPj4+IDgpIHwgKGdhbW1hMHhsIDw8IDI0KSkgXiAoZ2FtbWEweGggPj4+IDcpO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTBsICA9ICgoZ2FtbWEweGwgPj4+IDEpIHwgKGdhbW1hMHhoIDw8IDMxKSkgXiAoKGdhbW1hMHhsID4+PiA4KSB8IChnYW1tYTB4aCA8PCAyNCkpIF4gKChnYW1tYTB4bCA+Pj4gNykgfCAoZ2FtbWEweGggPDwgMjUpKTtcblxuXHQgICAgICAgICAgICAgICAgICAgIC8vIEdhbW1hMVxuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTF4ICA9IFdbaSAtIDJdO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTF4aCA9IGdhbW1hMXguaGlnaDtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgZ2FtbWExeGwgPSBnYW1tYTF4Lmxvdztcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgZ2FtbWExaCAgPSAoKGdhbW1hMXhoID4+PiAxOSkgfCAoZ2FtbWExeGwgPDwgMTMpKSBeICgoZ2FtbWExeGggPDwgMykgfCAoZ2FtbWExeGwgPj4+IDI5KSkgXiAoZ2FtbWExeGggPj4+IDYpO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBnYW1tYTFsICA9ICgoZ2FtbWExeGwgPj4+IDE5KSB8IChnYW1tYTF4aCA8PCAxMykpIF4gKChnYW1tYTF4bCA8PCAzKSB8IChnYW1tYTF4aCA+Pj4gMjkpKSBeICgoZ2FtbWExeGwgPj4+IDYpIHwgKGdhbW1hMXhoIDw8IDI2KSk7XG5cblx0ICAgICAgICAgICAgICAgICAgICAvLyBXW2ldID0gZ2FtbWEwICsgV1tpIC0gN10gKyBnYW1tYTEgKyBXW2kgLSAxNl1cblx0ICAgICAgICAgICAgICAgICAgICB2YXIgV2k3ICA9IFdbaSAtIDddO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBXaTdoID0gV2k3LmhpZ2g7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpN2wgPSBXaTcubG93O1xuXG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpMTYgID0gV1tpIC0gMTZdO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBXaTE2aCA9IFdpMTYuaGlnaDtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgV2kxNmwgPSBXaTE2LmxvdztcblxuXHQgICAgICAgICAgICAgICAgICAgIHZhciBXaWwgPSBnYW1tYTBsICsgV2k3bDtcblx0ICAgICAgICAgICAgICAgICAgICB2YXIgV2loID0gZ2FtbWEwaCArIFdpN2ggKyAoKFdpbCA+Pj4gMCkgPCAoZ2FtbWEwbCA+Pj4gMCkgPyAxIDogMCk7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpbCA9IFdpbCArIGdhbW1hMWw7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpaCA9IFdpaCArIGdhbW1hMWggKyAoKFdpbCA+Pj4gMCkgPCAoZ2FtbWExbCA+Pj4gMCkgPyAxIDogMCk7XG5cdCAgICAgICAgICAgICAgICAgICAgdmFyIFdpbCA9IFdpbCArIFdpMTZsO1xuXHQgICAgICAgICAgICAgICAgICAgIHZhciBXaWggPSBXaWggKyBXaTE2aCArICgoV2lsID4+PiAwKSA8IChXaTE2bCA+Pj4gMCkgPyAxIDogMCk7XG5cblx0ICAgICAgICAgICAgICAgICAgICBXaS5oaWdoID0gV2loO1xuXHQgICAgICAgICAgICAgICAgICAgIFdpLmxvdyAgPSBXaWw7XG5cdCAgICAgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgICAgIHZhciBjaGggID0gKGVoICYgZmgpIF4gKH5laCAmIGdoKTtcblx0ICAgICAgICAgICAgICAgIHZhciBjaGwgID0gKGVsICYgZmwpIF4gKH5lbCAmIGdsKTtcblx0ICAgICAgICAgICAgICAgIHZhciBtYWpoID0gKGFoICYgYmgpIF4gKGFoICYgY2gpIF4gKGJoICYgY2gpO1xuXHQgICAgICAgICAgICAgICAgdmFyIG1hamwgPSAoYWwgJiBibCkgXiAoYWwgJiBjbCkgXiAoYmwgJiBjbCk7XG5cblx0ICAgICAgICAgICAgICAgIHZhciBzaWdtYTBoID0gKChhaCA+Pj4gMjgpIHwgKGFsIDw8IDQpKSAgXiAoKGFoIDw8IDMwKSAgfCAoYWwgPj4+IDIpKSBeICgoYWggPDwgMjUpIHwgKGFsID4+PiA3KSk7XG5cdCAgICAgICAgICAgICAgICB2YXIgc2lnbWEwbCA9ICgoYWwgPj4+IDI4KSB8IChhaCA8PCA0KSkgIF4gKChhbCA8PCAzMCkgIHwgKGFoID4+PiAyKSkgXiAoKGFsIDw8IDI1KSB8IChhaCA+Pj4gNykpO1xuXHQgICAgICAgICAgICAgICAgdmFyIHNpZ21hMWggPSAoKGVoID4+PiAxNCkgfCAoZWwgPDwgMTgpKSBeICgoZWggPj4+IDE4KSB8IChlbCA8PCAxNCkpIF4gKChlaCA8PCAyMykgfCAoZWwgPj4+IDkpKTtcblx0ICAgICAgICAgICAgICAgIHZhciBzaWdtYTFsID0gKChlbCA+Pj4gMTQpIHwgKGVoIDw8IDE4KSkgXiAoKGVsID4+PiAxOCkgfCAoZWggPDwgMTQpKSBeICgoZWwgPDwgMjMpIHwgKGVoID4+PiA5KSk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIHQxID0gaCArIHNpZ21hMSArIGNoICsgS1tpXSArIFdbaV1cblx0ICAgICAgICAgICAgICAgIHZhciBLaSAgPSBLW2ldO1xuXHQgICAgICAgICAgICAgICAgdmFyIEtpaCA9IEtpLmhpZ2g7XG5cdCAgICAgICAgICAgICAgICB2YXIgS2lsID0gS2kubG93O1xuXG5cdCAgICAgICAgICAgICAgICB2YXIgdDFsID0gaGwgKyBzaWdtYTFsO1xuXHQgICAgICAgICAgICAgICAgdmFyIHQxaCA9IGhoICsgc2lnbWExaCArICgodDFsID4+PiAwKSA8IChobCA+Pj4gMCkgPyAxIDogMCk7XG5cdCAgICAgICAgICAgICAgICB2YXIgdDFsID0gdDFsICsgY2hsO1xuXHQgICAgICAgICAgICAgICAgdmFyIHQxaCA9IHQxaCArIGNoaCArICgodDFsID4+PiAwKSA8IChjaGwgPj4+IDApID8gMSA6IDApO1xuXHQgICAgICAgICAgICAgICAgdmFyIHQxbCA9IHQxbCArIEtpbDtcblx0ICAgICAgICAgICAgICAgIHZhciB0MWggPSB0MWggKyBLaWggKyAoKHQxbCA+Pj4gMCkgPCAoS2lsID4+PiAwKSA/IDEgOiAwKTtcblx0ICAgICAgICAgICAgICAgIHZhciB0MWwgPSB0MWwgKyBXaWw7XG5cdCAgICAgICAgICAgICAgICB2YXIgdDFoID0gdDFoICsgV2loICsgKCh0MWwgPj4+IDApIDwgKFdpbCA+Pj4gMCkgPyAxIDogMCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIHQyID0gc2lnbWEwICsgbWFqXG5cdCAgICAgICAgICAgICAgICB2YXIgdDJsID0gc2lnbWEwbCArIG1hamw7XG5cdCAgICAgICAgICAgICAgICB2YXIgdDJoID0gc2lnbWEwaCArIG1hamggKyAoKHQybCA+Pj4gMCkgPCAoc2lnbWEwbCA+Pj4gMCkgPyAxIDogMCk7XG5cblx0ICAgICAgICAgICAgICAgIC8vIFVwZGF0ZSB3b3JraW5nIHZhcmlhYmxlc1xuXHQgICAgICAgICAgICAgICAgaGggPSBnaDtcblx0ICAgICAgICAgICAgICAgIGhsID0gZ2w7XG5cdCAgICAgICAgICAgICAgICBnaCA9IGZoO1xuXHQgICAgICAgICAgICAgICAgZ2wgPSBmbDtcblx0ICAgICAgICAgICAgICAgIGZoID0gZWg7XG5cdCAgICAgICAgICAgICAgICBmbCA9IGVsO1xuXHQgICAgICAgICAgICAgICAgZWwgPSAoZGwgKyB0MWwpIHwgMDtcblx0ICAgICAgICAgICAgICAgIGVoID0gKGRoICsgdDFoICsgKChlbCA+Pj4gMCkgPCAoZGwgPj4+IDApID8gMSA6IDApKSB8IDA7XG5cdCAgICAgICAgICAgICAgICBkaCA9IGNoO1xuXHQgICAgICAgICAgICAgICAgZGwgPSBjbDtcblx0ICAgICAgICAgICAgICAgIGNoID0gYmg7XG5cdCAgICAgICAgICAgICAgICBjbCA9IGJsO1xuXHQgICAgICAgICAgICAgICAgYmggPSBhaDtcblx0ICAgICAgICAgICAgICAgIGJsID0gYWw7XG5cdCAgICAgICAgICAgICAgICBhbCA9ICh0MWwgKyB0MmwpIHwgMDtcblx0ICAgICAgICAgICAgICAgIGFoID0gKHQxaCArIHQyaCArICgoYWwgPj4+IDApIDwgKHQxbCA+Pj4gMCkgPyAxIDogMCkpIHwgMDtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEludGVybWVkaWF0ZSBoYXNoIHZhbHVlXG5cdCAgICAgICAgICAgIEgwbCA9IEgwLmxvdyAgPSAoSDBsICsgYWwpO1xuXHQgICAgICAgICAgICBIMC5oaWdoID0gKEgwaCArIGFoICsgKChIMGwgPj4+IDApIDwgKGFsID4+PiAwKSA/IDEgOiAwKSk7XG5cdCAgICAgICAgICAgIEgxbCA9IEgxLmxvdyAgPSAoSDFsICsgYmwpO1xuXHQgICAgICAgICAgICBIMS5oaWdoID0gKEgxaCArIGJoICsgKChIMWwgPj4+IDApIDwgKGJsID4+PiAwKSA/IDEgOiAwKSk7XG5cdCAgICAgICAgICAgIEgybCA9IEgyLmxvdyAgPSAoSDJsICsgY2wpO1xuXHQgICAgICAgICAgICBIMi5oaWdoID0gKEgyaCArIGNoICsgKChIMmwgPj4+IDApIDwgKGNsID4+PiAwKSA/IDEgOiAwKSk7XG5cdCAgICAgICAgICAgIEgzbCA9IEgzLmxvdyAgPSAoSDNsICsgZGwpO1xuXHQgICAgICAgICAgICBIMy5oaWdoID0gKEgzaCArIGRoICsgKChIM2wgPj4+IDApIDwgKGRsID4+PiAwKSA/IDEgOiAwKSk7XG5cdCAgICAgICAgICAgIEg0bCA9IEg0LmxvdyAgPSAoSDRsICsgZWwpO1xuXHQgICAgICAgICAgICBINC5oaWdoID0gKEg0aCArIGVoICsgKChINGwgPj4+IDApIDwgKGVsID4+PiAwKSA/IDEgOiAwKSk7XG5cdCAgICAgICAgICAgIEg1bCA9IEg1LmxvdyAgPSAoSDVsICsgZmwpO1xuXHQgICAgICAgICAgICBINS5oaWdoID0gKEg1aCArIGZoICsgKChINWwgPj4+IDApIDwgKGZsID4+PiAwKSA/IDEgOiAwKSk7XG5cdCAgICAgICAgICAgIEg2bCA9IEg2LmxvdyAgPSAoSDZsICsgZ2wpO1xuXHQgICAgICAgICAgICBINi5oaWdoID0gKEg2aCArIGdoICsgKChINmwgPj4+IDApIDwgKGdsID4+PiAwKSA/IDEgOiAwKSk7XG5cdCAgICAgICAgICAgIEg3bCA9IEg3LmxvdyAgPSAoSDdsICsgaGwpO1xuXHQgICAgICAgICAgICBINy5oaWdoID0gKEg3aCArIGhoICsgKChIN2wgPj4+IDApIDwgKGhsID4+PiAwKSA/IDEgOiAwKSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIF9kb0ZpbmFsaXplOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIgZGF0YSA9IHRoaXMuX2RhdGE7XG5cdCAgICAgICAgICAgIHZhciBkYXRhV29yZHMgPSBkYXRhLndvcmRzO1xuXG5cdCAgICAgICAgICAgIHZhciBuQml0c1RvdGFsID0gdGhpcy5fbkRhdGFCeXRlcyAqIDg7XG5cdCAgICAgICAgICAgIHZhciBuQml0c0xlZnQgPSBkYXRhLnNpZ0J5dGVzICogODtcblxuXHQgICAgICAgICAgICAvLyBBZGQgcGFkZGluZ1xuXHQgICAgICAgICAgICBkYXRhV29yZHNbbkJpdHNMZWZ0ID4+PiA1XSB8PSAweDgwIDw8ICgyNCAtIG5CaXRzTGVmdCAlIDMyKTtcblx0ICAgICAgICAgICAgZGF0YVdvcmRzWygoKG5CaXRzTGVmdCArIDEyOCkgPj4+IDEwKSA8PCA1KSArIDMwXSA9IE1hdGguZmxvb3IobkJpdHNUb3RhbCAvIDB4MTAwMDAwMDAwKTtcblx0ICAgICAgICAgICAgZGF0YVdvcmRzWygoKG5CaXRzTGVmdCArIDEyOCkgPj4+IDEwKSA8PCA1KSArIDMxXSA9IG5CaXRzVG90YWw7XG5cdCAgICAgICAgICAgIGRhdGEuc2lnQnl0ZXMgPSBkYXRhV29yZHMubGVuZ3RoICogNDtcblxuXHQgICAgICAgICAgICAvLyBIYXNoIGZpbmFsIGJsb2Nrc1xuXHQgICAgICAgICAgICB0aGlzLl9wcm9jZXNzKCk7XG5cblx0ICAgICAgICAgICAgLy8gQ29udmVydCBoYXNoIHRvIDMyLWJpdCB3b3JkIGFycmF5IGJlZm9yZSByZXR1cm5pbmdcblx0ICAgICAgICAgICAgdmFyIGhhc2ggPSB0aGlzLl9oYXNoLnRvWDMyKCk7XG5cblx0ICAgICAgICAgICAgLy8gUmV0dXJuIGZpbmFsIGNvbXB1dGVkIGhhc2hcblx0ICAgICAgICAgICAgcmV0dXJuIGhhc2g7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGNsb25lOiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIHZhciBjbG9uZSA9IEhhc2hlci5jbG9uZS5jYWxsKHRoaXMpO1xuXHQgICAgICAgICAgICBjbG9uZS5faGFzaCA9IHRoaXMuX2hhc2guY2xvbmUoKTtcblxuXHQgICAgICAgICAgICByZXR1cm4gY2xvbmU7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGJsb2NrU2l6ZTogMTAyNC8zMlxuXHQgICAgfSk7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIGhhc2hlcidzIG9iamVjdCBpbnRlcmZhY2UuXG5cdCAgICAgKlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBtZXNzYWdlIFRoZSBtZXNzYWdlIHRvIGhhc2guXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgaGFzaC5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhhc2ggPSBDcnlwdG9KUy5TSEE1MTIoJ21lc3NhZ2UnKTtcblx0ICAgICAqICAgICB2YXIgaGFzaCA9IENyeXB0b0pTLlNIQTUxMih3b3JkQXJyYXkpO1xuXHQgICAgICovXG5cdCAgICBDLlNIQTUxMiA9IEhhc2hlci5fY3JlYXRlSGVscGVyKFNIQTUxMik7XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb24gdG8gdGhlIEhNQUMncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBwYXJhbSB7V29yZEFycmF5fHN0cmluZ30gbWVzc2FnZSBUaGUgbWVzc2FnZSB0byBoYXNoLlxuXHQgICAgICogQHBhcmFtIHtXb3JkQXJyYXl8c3RyaW5nfSBrZXkgVGhlIHNlY3JldCBrZXkuXG5cdCAgICAgKlxuXHQgICAgICogQHJldHVybiB7V29yZEFycmF5fSBUaGUgSE1BQy5cblx0ICAgICAqXG5cdCAgICAgKiBAc3RhdGljXG5cdCAgICAgKlxuXHQgICAgICogQGV4YW1wbGVcblx0ICAgICAqXG5cdCAgICAgKiAgICAgdmFyIGhtYWMgPSBDcnlwdG9KUy5IbWFjU0hBNTEyKG1lc3NhZ2UsIGtleSk7XG5cdCAgICAgKi9cblx0ICAgIEMuSG1hY1NIQTUxMiA9IEhhc2hlci5fY3JlYXRlSG1hY0hlbHBlcihTSEE1MTIpO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTLlNIQTUxMjtcblxufSkpOyIsIjsoZnVuY3Rpb24gKHJvb3QsIGZhY3RvcnksIHVuZGVmKSB7XG5cdGlmICh0eXBlb2YgZXhwb3J0cyA9PT0gXCJvYmplY3RcIikge1xuXHRcdC8vIENvbW1vbkpTXG5cdFx0bW9kdWxlLmV4cG9ydHMgPSBleHBvcnRzID0gZmFjdG9yeShyZXF1aXJlKFwiLi9jb3JlXCIpLCByZXF1aXJlKFwiLi9lbmMtYmFzZTY0XCIpLCByZXF1aXJlKFwiLi9tZDVcIiksIHJlcXVpcmUoXCIuL2V2cGtkZlwiKSwgcmVxdWlyZShcIi4vY2lwaGVyLWNvcmVcIikpO1xuXHR9XG5cdGVsc2UgaWYgKHR5cGVvZiBkZWZpbmUgPT09IFwiZnVuY3Rpb25cIiAmJiBkZWZpbmUuYW1kKSB7XG5cdFx0Ly8gQU1EXG5cdFx0ZGVmaW5lKFtcIi4vY29yZVwiLCBcIi4vZW5jLWJhc2U2NFwiLCBcIi4vbWQ1XCIsIFwiLi9ldnBrZGZcIiwgXCIuL2NpcGhlci1jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5O1xuXHQgICAgdmFyIEJsb2NrQ2lwaGVyID0gQ19saWIuQmxvY2tDaXBoZXI7XG5cdCAgICB2YXIgQ19hbGdvID0gQy5hbGdvO1xuXG5cdCAgICAvLyBQZXJtdXRlZCBDaG9pY2UgMSBjb25zdGFudHNcblx0ICAgIHZhciBQQzEgPSBbXG5cdCAgICAgICAgNTcsIDQ5LCA0MSwgMzMsIDI1LCAxNywgOSwgIDEsXG5cdCAgICAgICAgNTgsIDUwLCA0MiwgMzQsIDI2LCAxOCwgMTAsIDIsXG5cdCAgICAgICAgNTksIDUxLCA0MywgMzUsIDI3LCAxOSwgMTEsIDMsXG5cdCAgICAgICAgNjAsIDUyLCA0NCwgMzYsIDYzLCA1NSwgNDcsIDM5LFxuXHQgICAgICAgIDMxLCAyMywgMTUsIDcsICA2MiwgNTQsIDQ2LCAzOCxcblx0ICAgICAgICAzMCwgMjIsIDE0LCA2LCAgNjEsIDUzLCA0NSwgMzcsXG5cdCAgICAgICAgMjksIDIxLCAxMywgNSwgIDI4LCAyMCwgMTIsIDRcblx0ICAgIF07XG5cblx0ICAgIC8vIFBlcm11dGVkIENob2ljZSAyIGNvbnN0YW50c1xuXHQgICAgdmFyIFBDMiA9IFtcblx0ICAgICAgICAxNCwgMTcsIDExLCAyNCwgMSwgIDUsXG5cdCAgICAgICAgMywgIDI4LCAxNSwgNiwgIDIxLCAxMCxcblx0ICAgICAgICAyMywgMTksIDEyLCA0LCAgMjYsIDgsXG5cdCAgICAgICAgMTYsIDcsICAyNywgMjAsIDEzLCAyLFxuXHQgICAgICAgIDQxLCA1MiwgMzEsIDM3LCA0NywgNTUsXG5cdCAgICAgICAgMzAsIDQwLCA1MSwgNDUsIDMzLCA0OCxcblx0ICAgICAgICA0NCwgNDksIDM5LCA1NiwgMzQsIDUzLFxuXHQgICAgICAgIDQ2LCA0MiwgNTAsIDM2LCAyOSwgMzJcblx0ICAgIF07XG5cblx0ICAgIC8vIEN1bXVsYXRpdmUgYml0IHNoaWZ0IGNvbnN0YW50c1xuXHQgICAgdmFyIEJJVF9TSElGVFMgPSBbMSwgIDIsICA0LCAgNiwgIDgsICAxMCwgMTIsIDE0LCAxNSwgMTcsIDE5LCAyMSwgMjMsIDI1LCAyNywgMjhdO1xuXG5cdCAgICAvLyBTQk9YZXMgYW5kIHJvdW5kIHBlcm11dGF0aW9uIGNvbnN0YW50c1xuXHQgICAgdmFyIFNCT1hfUCA9IFtcblx0ICAgICAgICB7XG5cdCAgICAgICAgICAgIDB4MDogMHg4MDgyMDAsXG5cdCAgICAgICAgICAgIDB4MTAwMDAwMDA6IDB4ODAwMCxcblx0ICAgICAgICAgICAgMHgyMDAwMDAwMDogMHg4MDgwMDIsXG5cdCAgICAgICAgICAgIDB4MzAwMDAwMDA6IDB4Mixcblx0ICAgICAgICAgICAgMHg0MDAwMDAwMDogMHgyMDAsXG5cdCAgICAgICAgICAgIDB4NTAwMDAwMDA6IDB4ODA4MjAyLFxuXHQgICAgICAgICAgICAweDYwMDAwMDAwOiAweDgwMDIwMixcblx0ICAgICAgICAgICAgMHg3MDAwMDAwMDogMHg4MDAwMDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMDA6IDB4MjAyLFxuXHQgICAgICAgICAgICAweDkwMDAwMDAwOiAweDgwMDIwMCxcblx0ICAgICAgICAgICAgMHhhMDAwMDAwMDogMHg4MjAwLFxuXHQgICAgICAgICAgICAweGIwMDAwMDAwOiAweDgwODAwMCxcblx0ICAgICAgICAgICAgMHhjMDAwMDAwMDogMHg4MDAyLFxuXHQgICAgICAgICAgICAweGQwMDAwMDAwOiAweDgwMDAwMixcblx0ICAgICAgICAgICAgMHhlMDAwMDAwMDogMHgwLFxuXHQgICAgICAgICAgICAweGYwMDAwMDAwOiAweDgyMDIsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMDogMHgwLFxuXHQgICAgICAgICAgICAweDE4MDAwMDAwOiAweDgwODIwMixcblx0ICAgICAgICAgICAgMHgyODAwMDAwMDogMHg4MjAyLFxuXHQgICAgICAgICAgICAweDM4MDAwMDAwOiAweDgwMDAsXG5cdCAgICAgICAgICAgIDB4NDgwMDAwMDA6IDB4ODA4MjAwLFxuXHQgICAgICAgICAgICAweDU4MDAwMDAwOiAweDIwMCxcblx0ICAgICAgICAgICAgMHg2ODAwMDAwMDogMHg4MDgwMDIsXG5cdCAgICAgICAgICAgIDB4NzgwMDAwMDA6IDB4Mixcblx0ICAgICAgICAgICAgMHg4ODAwMDAwMDogMHg4MDAyMDAsXG5cdCAgICAgICAgICAgIDB4OTgwMDAwMDA6IDB4ODIwMCxcblx0ICAgICAgICAgICAgMHhhODAwMDAwMDogMHg4MDgwMDAsXG5cdCAgICAgICAgICAgIDB4YjgwMDAwMDA6IDB4ODAwMjAyLFxuXHQgICAgICAgICAgICAweGM4MDAwMDAwOiAweDgwMDAwMixcblx0ICAgICAgICAgICAgMHhkODAwMDAwMDogMHg4MDAyLFxuXHQgICAgICAgICAgICAweGU4MDAwMDAwOiAweDIwMixcblx0ICAgICAgICAgICAgMHhmODAwMDAwMDogMHg4MDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTogMHg4MDAwLFxuXHQgICAgICAgICAgICAweDEwMDAwMDAxOiAweDIsXG5cdCAgICAgICAgICAgIDB4MjAwMDAwMDE6IDB4ODA4MjAwLFxuXHQgICAgICAgICAgICAweDMwMDAwMDAxOiAweDgwMDAwMCxcblx0ICAgICAgICAgICAgMHg0MDAwMDAwMTogMHg4MDgwMDIsXG5cdCAgICAgICAgICAgIDB4NTAwMDAwMDE6IDB4ODIwMCxcblx0ICAgICAgICAgICAgMHg2MDAwMDAwMTogMHgyMDAsXG5cdCAgICAgICAgICAgIDB4NzAwMDAwMDE6IDB4ODAwMjAyLFxuXHQgICAgICAgICAgICAweDgwMDAwMDAxOiAweDgwODIwMixcblx0ICAgICAgICAgICAgMHg5MDAwMDAwMTogMHg4MDgwMDAsXG5cdCAgICAgICAgICAgIDB4YTAwMDAwMDE6IDB4ODAwMDAyLFxuXHQgICAgICAgICAgICAweGIwMDAwMDAxOiAweDgyMDIsXG5cdCAgICAgICAgICAgIDB4YzAwMDAwMDE6IDB4MjAyLFxuXHQgICAgICAgICAgICAweGQwMDAwMDAxOiAweDgwMDIwMCxcblx0ICAgICAgICAgICAgMHhlMDAwMDAwMTogMHg4MDAyLFxuXHQgICAgICAgICAgICAweGYwMDAwMDAxOiAweDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMTogMHg4MDgyMDIsXG5cdCAgICAgICAgICAgIDB4MTgwMDAwMDE6IDB4ODA4MDAwLFxuXHQgICAgICAgICAgICAweDI4MDAwMDAxOiAweDgwMDAwMCxcblx0ICAgICAgICAgICAgMHgzODAwMDAwMTogMHgyMDAsXG5cdCAgICAgICAgICAgIDB4NDgwMDAwMDE6IDB4ODAwMCxcblx0ICAgICAgICAgICAgMHg1ODAwMDAwMTogMHg4MDAwMDIsXG5cdCAgICAgICAgICAgIDB4NjgwMDAwMDE6IDB4Mixcblx0ICAgICAgICAgICAgMHg3ODAwMDAwMTogMHg4MjAyLFxuXHQgICAgICAgICAgICAweDg4MDAwMDAxOiAweDgwMDIsXG5cdCAgICAgICAgICAgIDB4OTgwMDAwMDE6IDB4ODAwMjAyLFxuXHQgICAgICAgICAgICAweGE4MDAwMDAxOiAweDIwMixcblx0ICAgICAgICAgICAgMHhiODAwMDAwMTogMHg4MDgyMDAsXG5cdCAgICAgICAgICAgIDB4YzgwMDAwMDE6IDB4ODAwMjAwLFxuXHQgICAgICAgICAgICAweGQ4MDAwMDAxOiAweDAsXG5cdCAgICAgICAgICAgIDB4ZTgwMDAwMDE6IDB4ODIwMCxcblx0ICAgICAgICAgICAgMHhmODAwMDAwMTogMHg4MDgwMDJcblx0ICAgICAgICB9LFxuXHQgICAgICAgIHtcblx0ICAgICAgICAgICAgMHgwOiAweDQwMDg0MDEwLFxuXHQgICAgICAgICAgICAweDEwMDAwMDA6IDB4NDAwMCxcblx0ICAgICAgICAgICAgMHgyMDAwMDAwOiAweDgwMDAwLFxuXHQgICAgICAgICAgICAweDMwMDAwMDA6IDB4NDAwODAwMTAsXG5cdCAgICAgICAgICAgIDB4NDAwMDAwMDogMHg0MDAwMDAxMCxcblx0ICAgICAgICAgICAgMHg1MDAwMDAwOiAweDQwMDg0MDAwLFxuXHQgICAgICAgICAgICAweDYwMDAwMDA6IDB4NDAwMDQwMDAsXG5cdCAgICAgICAgICAgIDB4NzAwMDAwMDogMHgxMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwOiAweDg0MDAwLFxuXHQgICAgICAgICAgICAweDkwMDAwMDA6IDB4NDAwMDQwMTAsXG5cdCAgICAgICAgICAgIDB4YTAwMDAwMDogMHg0MDAwMDAwMCxcblx0ICAgICAgICAgICAgMHhiMDAwMDAwOiAweDg0MDEwLFxuXHQgICAgICAgICAgICAweGMwMDAwMDA6IDB4ODAwMTAsXG5cdCAgICAgICAgICAgIDB4ZDAwMDAwMDogMHgwLFxuXHQgICAgICAgICAgICAweGUwMDAwMDA6IDB4NDAxMCxcblx0ICAgICAgICAgICAgMHhmMDAwMDAwOiAweDQwMDgwMDAwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDogMHg0MDAwNDAwMCxcblx0ICAgICAgICAgICAgMHgxODAwMDAwOiAweDg0MDEwLFxuXHQgICAgICAgICAgICAweDI4MDAwMDA6IDB4MTAsXG5cdCAgICAgICAgICAgIDB4MzgwMDAwMDogMHg0MDAwNDAxMCxcblx0ICAgICAgICAgICAgMHg0ODAwMDAwOiAweDQwMDg0MDEwLFxuXHQgICAgICAgICAgICAweDU4MDAwMDA6IDB4NDAwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4NjgwMDAwMDogMHg4MDAwMCxcblx0ICAgICAgICAgICAgMHg3ODAwMDAwOiAweDQwMDgwMDEwLFxuXHQgICAgICAgICAgICAweDg4MDAwMDA6IDB4ODAwMTAsXG5cdCAgICAgICAgICAgIDB4OTgwMDAwMDogMHgwLFxuXHQgICAgICAgICAgICAweGE4MDAwMDA6IDB4NDAwMCxcblx0ICAgICAgICAgICAgMHhiODAwMDAwOiAweDQwMDgwMDAwLFxuXHQgICAgICAgICAgICAweGM4MDAwMDA6IDB4NDAwMDAwMTAsXG5cdCAgICAgICAgICAgIDB4ZDgwMDAwMDogMHg4NDAwMCxcblx0ICAgICAgICAgICAgMHhlODAwMDAwOiAweDQwMDg0MDAwLFxuXHQgICAgICAgICAgICAweGY4MDAwMDA6IDB4NDAxMCxcblx0ICAgICAgICAgICAgMHgxMDAwMDAwMDogMHgwLFxuXHQgICAgICAgICAgICAweDExMDAwMDAwOiAweDQwMDgwMDEwLFxuXHQgICAgICAgICAgICAweDEyMDAwMDAwOiAweDQwMDA0MDEwLFxuXHQgICAgICAgICAgICAweDEzMDAwMDAwOiAweDQwMDg0MDAwLFxuXHQgICAgICAgICAgICAweDE0MDAwMDAwOiAweDQwMDgwMDAwLFxuXHQgICAgICAgICAgICAweDE1MDAwMDAwOiAweDEwLFxuXHQgICAgICAgICAgICAweDE2MDAwMDAwOiAweDg0MDEwLFxuXHQgICAgICAgICAgICAweDE3MDAwMDAwOiAweDQwMDAsXG5cdCAgICAgICAgICAgIDB4MTgwMDAwMDA6IDB4NDAxMCxcblx0ICAgICAgICAgICAgMHgxOTAwMDAwMDogMHg4MDAwMCxcblx0ICAgICAgICAgICAgMHgxYTAwMDAwMDogMHg4MDAxMCxcblx0ICAgICAgICAgICAgMHgxYjAwMDAwMDogMHg0MDAwMDAxMCxcblx0ICAgICAgICAgICAgMHgxYzAwMDAwMDogMHg4NDAwMCxcblx0ICAgICAgICAgICAgMHgxZDAwMDAwMDogMHg0MDAwNDAwMCxcblx0ICAgICAgICAgICAgMHgxZTAwMDAwMDogMHg0MDAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxZjAwMDAwMDogMHg0MDA4NDAxMCxcblx0ICAgICAgICAgICAgMHgxMDgwMDAwMDogMHg4NDAxMCxcblx0ICAgICAgICAgICAgMHgxMTgwMDAwMDogMHg4MDAwMCxcblx0ICAgICAgICAgICAgMHgxMjgwMDAwMDogMHg0MDA4MDAwMCxcblx0ICAgICAgICAgICAgMHgxMzgwMDAwMDogMHg0MDAwLFxuXHQgICAgICAgICAgICAweDE0ODAwMDAwOiAweDQwMDA0MDAwLFxuXHQgICAgICAgICAgICAweDE1ODAwMDAwOiAweDQwMDg0MDEwLFxuXHQgICAgICAgICAgICAweDE2ODAwMDAwOiAweDEwLFxuXHQgICAgICAgICAgICAweDE3ODAwMDAwOiAweDQwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDE4ODAwMDAwOiAweDQwMDg0MDAwLFxuXHQgICAgICAgICAgICAweDE5ODAwMDAwOiAweDQwMDAwMDEwLFxuXHQgICAgICAgICAgICAweDFhODAwMDAwOiAweDQwMDA0MDEwLFxuXHQgICAgICAgICAgICAweDFiODAwMDAwOiAweDgwMDEwLFxuXHQgICAgICAgICAgICAweDFjODAwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MWQ4MDAwMDA6IDB4NDAxMCxcblx0ICAgICAgICAgICAgMHgxZTgwMDAwMDogMHg0MDA4MDAxMCxcblx0ICAgICAgICAgICAgMHgxZjgwMDAwMDogMHg4NDAwMFxuXHQgICAgICAgIH0sXG5cdCAgICAgICAge1xuXHQgICAgICAgICAgICAweDA6IDB4MTA0LFxuXHQgICAgICAgICAgICAweDEwMDAwMDogMHgwLFxuXHQgICAgICAgICAgICAweDIwMDAwMDogMHg0MDAwMTAwLFxuXHQgICAgICAgICAgICAweDMwMDAwMDogMHgxMDEwNCxcblx0ICAgICAgICAgICAgMHg0MDAwMDA6IDB4MTAwMDQsXG5cdCAgICAgICAgICAgIDB4NTAwMDAwOiAweDQwMDAwMDQsXG5cdCAgICAgICAgICAgIDB4NjAwMDAwOiAweDQwMTAxMDQsXG5cdCAgICAgICAgICAgIDB4NzAwMDAwOiAweDQwMTAwMDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwOiAweDQwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4OTAwMDAwOiAweDQwMTAxMDAsXG5cdCAgICAgICAgICAgIDB4YTAwMDAwOiAweDEwMTAwLFxuXHQgICAgICAgICAgICAweGIwMDAwMDogMHg0MDEwMDA0LFxuXHQgICAgICAgICAgICAweGMwMDAwMDogMHg0MDAwMTA0LFxuXHQgICAgICAgICAgICAweGQwMDAwMDogMHgxMDAwMCxcblx0ICAgICAgICAgICAgMHhlMDAwMDA6IDB4NCxcblx0ICAgICAgICAgICAgMHhmMDAwMDA6IDB4MTAwLFxuXHQgICAgICAgICAgICAweDgwMDAwOiAweDQwMTAxMDAsXG5cdCAgICAgICAgICAgIDB4MTgwMDAwOiAweDQwMTAwMDQsXG5cdCAgICAgICAgICAgIDB4MjgwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MzgwMDAwOiAweDQwMDAxMDAsXG5cdCAgICAgICAgICAgIDB4NDgwMDAwOiAweDQwMDAwMDQsXG5cdCAgICAgICAgICAgIDB4NTgwMDAwOiAweDEwMDAwLFxuXHQgICAgICAgICAgICAweDY4MDAwMDogMHgxMDAwNCxcblx0ICAgICAgICAgICAgMHg3ODAwMDA6IDB4MTA0LFxuXHQgICAgICAgICAgICAweDg4MDAwMDogMHg0LFxuXHQgICAgICAgICAgICAweDk4MDAwMDogMHgxMDAsXG5cdCAgICAgICAgICAgIDB4YTgwMDAwOiAweDQwMTAwMDAsXG5cdCAgICAgICAgICAgIDB4YjgwMDAwOiAweDEwMTA0LFxuXHQgICAgICAgICAgICAweGM4MDAwMDogMHgxMDEwMCxcblx0ICAgICAgICAgICAgMHhkODAwMDA6IDB4NDAwMDEwNCxcblx0ICAgICAgICAgICAgMHhlODAwMDA6IDB4NDAxMDEwNCxcblx0ICAgICAgICAgICAgMHhmODAwMDA6IDB4NDAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxMDAwMDAwOiAweDQwMTAxMDAsXG5cdCAgICAgICAgICAgIDB4MTEwMDAwMDogMHgxMDAwNCxcblx0ICAgICAgICAgICAgMHgxMjAwMDAwOiAweDEwMDAwLFxuXHQgICAgICAgICAgICAweDEzMDAwMDA6IDB4NDAwMDEwMCxcblx0ICAgICAgICAgICAgMHgxNDAwMDAwOiAweDEwMCxcblx0ICAgICAgICAgICAgMHgxNTAwMDAwOiAweDQwMTAxMDQsXG5cdCAgICAgICAgICAgIDB4MTYwMDAwMDogMHg0MDAwMDA0LFxuXHQgICAgICAgICAgICAweDE3MDAwMDA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxODAwMDAwOiAweDQwMDAxMDQsXG5cdCAgICAgICAgICAgIDB4MTkwMDAwMDogMHg0MDAwMDAwLFxuXHQgICAgICAgICAgICAweDFhMDAwMDA6IDB4NCxcblx0ICAgICAgICAgICAgMHgxYjAwMDAwOiAweDEwMTAwLFxuXHQgICAgICAgICAgICAweDFjMDAwMDA6IDB4NDAxMDAwMCxcblx0ICAgICAgICAgICAgMHgxZDAwMDAwOiAweDEwNCxcblx0ICAgICAgICAgICAgMHgxZTAwMDAwOiAweDEwMTA0LFxuXHQgICAgICAgICAgICAweDFmMDAwMDA6IDB4NDAxMDAwNCxcblx0ICAgICAgICAgICAgMHgxMDgwMDAwOiAweDQwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTE4MDAwMDogMHgxMDQsXG5cdCAgICAgICAgICAgIDB4MTI4MDAwMDogMHg0MDEwMTAwLFxuXHQgICAgICAgICAgICAweDEzODAwMDA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxNDgwMDAwOiAweDEwMDA0LFxuXHQgICAgICAgICAgICAweDE1ODAwMDA6IDB4NDAwMDEwMCxcblx0ICAgICAgICAgICAgMHgxNjgwMDAwOiAweDEwMCxcblx0ICAgICAgICAgICAgMHgxNzgwMDAwOiAweDQwMTAwMDQsXG5cdCAgICAgICAgICAgIDB4MTg4MDAwMDogMHgxMDAwMCxcblx0ICAgICAgICAgICAgMHgxOTgwMDAwOiAweDQwMTAxMDQsXG5cdCAgICAgICAgICAgIDB4MWE4MDAwMDogMHgxMDEwNCxcblx0ICAgICAgICAgICAgMHgxYjgwMDAwOiAweDQwMDAwMDQsXG5cdCAgICAgICAgICAgIDB4MWM4MDAwMDogMHg0MDAwMTA0LFxuXHQgICAgICAgICAgICAweDFkODAwMDA6IDB4NDAxMDAwMCxcblx0ICAgICAgICAgICAgMHgxZTgwMDAwOiAweDQsXG5cdCAgICAgICAgICAgIDB4MWY4MDAwMDogMHgxMDEwMFxuXHQgICAgICAgIH0sXG5cdCAgICAgICAge1xuXHQgICAgICAgICAgICAweDA6IDB4ODA0MDEwMDAsXG5cdCAgICAgICAgICAgIDB4MTAwMDA6IDB4ODAwMDEwNDAsXG5cdCAgICAgICAgICAgIDB4MjAwMDA6IDB4NDAxMDQwLFxuXHQgICAgICAgICAgICAweDMwMDAwOiAweDgwNDAwMDAwLFxuXHQgICAgICAgICAgICAweDQwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4NTAwMDA6IDB4NDAxMDAwLFxuXHQgICAgICAgICAgICAweDYwMDAwOiAweDgwMDAwMDQwLFxuXHQgICAgICAgICAgICAweDcwMDAwOiAweDQwMDA0MCxcblx0ICAgICAgICAgICAgMHg4MDAwMDogMHg4MDAwMDAwMCxcblx0ICAgICAgICAgICAgMHg5MDAwMDogMHg0MDAwMDAsXG5cdCAgICAgICAgICAgIDB4YTAwMDA6IDB4NDAsXG5cdCAgICAgICAgICAgIDB4YjAwMDA6IDB4ODAwMDEwMDAsXG5cdCAgICAgICAgICAgIDB4YzAwMDA6IDB4ODA0MDAwNDAsXG5cdCAgICAgICAgICAgIDB4ZDAwMDA6IDB4MTA0MCxcblx0ICAgICAgICAgICAgMHhlMDAwMDogMHgxMDAwLFxuXHQgICAgICAgICAgICAweGYwMDAwOiAweDgwNDAxMDQwLFxuXHQgICAgICAgICAgICAweDgwMDA6IDB4ODAwMDEwNDAsXG5cdCAgICAgICAgICAgIDB4MTgwMDA6IDB4NDAsXG5cdCAgICAgICAgICAgIDB4MjgwMDA6IDB4ODA0MDAwNDAsXG5cdCAgICAgICAgICAgIDB4MzgwMDA6IDB4ODAwMDEwMDAsXG5cdCAgICAgICAgICAgIDB4NDgwMDA6IDB4NDAxMDAwLFxuXHQgICAgICAgICAgICAweDU4MDAwOiAweDgwNDAxMDQwLFxuXHQgICAgICAgICAgICAweDY4MDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4NzgwMDA6IDB4ODA0MDAwMDAsXG5cdCAgICAgICAgICAgIDB4ODgwMDA6IDB4MTAwMCxcblx0ICAgICAgICAgICAgMHg5ODAwMDogMHg4MDQwMTAwMCxcblx0ICAgICAgICAgICAgMHhhODAwMDogMHg0MDAwMDAsXG5cdCAgICAgICAgICAgIDB4YjgwMDA6IDB4MTA0MCxcblx0ICAgICAgICAgICAgMHhjODAwMDogMHg4MDAwMDAwMCxcblx0ICAgICAgICAgICAgMHhkODAwMDogMHg0MDAwNDAsXG5cdCAgICAgICAgICAgIDB4ZTgwMDA6IDB4NDAxMDQwLFxuXHQgICAgICAgICAgICAweGY4MDAwOiAweDgwMDAwMDQwLFxuXHQgICAgICAgICAgICAweDEwMDAwMDogMHg0MDAwNDAsXG5cdCAgICAgICAgICAgIDB4MTEwMDAwOiAweDQwMTAwMCxcblx0ICAgICAgICAgICAgMHgxMjAwMDA6IDB4ODAwMDAwNDAsXG5cdCAgICAgICAgICAgIDB4MTMwMDAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MTQwMDAwOiAweDEwNDAsXG5cdCAgICAgICAgICAgIDB4MTUwMDAwOiAweDgwNDAwMDQwLFxuXHQgICAgICAgICAgICAweDE2MDAwMDogMHg4MDQwMTAwMCxcblx0ICAgICAgICAgICAgMHgxNzAwMDA6IDB4ODAwMDEwNDAsXG5cdCAgICAgICAgICAgIDB4MTgwMDAwOiAweDgwNDAxMDQwLFxuXHQgICAgICAgICAgICAweDE5MDAwMDogMHg4MDAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxYTAwMDA6IDB4ODA0MDAwMDAsXG5cdCAgICAgICAgICAgIDB4MWIwMDAwOiAweDQwMTA0MCxcblx0ICAgICAgICAgICAgMHgxYzAwMDA6IDB4ODAwMDEwMDAsXG5cdCAgICAgICAgICAgIDB4MWQwMDAwOiAweDQwMDAwMCxcblx0ICAgICAgICAgICAgMHgxZTAwMDA6IDB4NDAsXG5cdCAgICAgICAgICAgIDB4MWYwMDAwOiAweDEwMDAsXG5cdCAgICAgICAgICAgIDB4MTA4MDAwOiAweDgwNDAwMDAwLFxuXHQgICAgICAgICAgICAweDExODAwMDogMHg4MDQwMTA0MCxcblx0ICAgICAgICAgICAgMHgxMjgwMDA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxMzgwMDA6IDB4NDAxMDAwLFxuXHQgICAgICAgICAgICAweDE0ODAwMDogMHg0MDAwNDAsXG5cdCAgICAgICAgICAgIDB4MTU4MDAwOiAweDgwMDAwMDAwLFxuXHQgICAgICAgICAgICAweDE2ODAwMDogMHg4MDAwMTA0MCxcblx0ICAgICAgICAgICAgMHgxNzgwMDA6IDB4NDAsXG5cdCAgICAgICAgICAgIDB4MTg4MDAwOiAweDgwMDAwMDQwLFxuXHQgICAgICAgICAgICAweDE5ODAwMDogMHgxMDAwLFxuXHQgICAgICAgICAgICAweDFhODAwMDogMHg4MDAwMTAwMCxcblx0ICAgICAgICAgICAgMHgxYjgwMDA6IDB4ODA0MDAwNDAsXG5cdCAgICAgICAgICAgIDB4MWM4MDAwOiAweDEwNDAsXG5cdCAgICAgICAgICAgIDB4MWQ4MDAwOiAweDgwNDAxMDAwLFxuXHQgICAgICAgICAgICAweDFlODAwMDogMHg0MDAwMDAsXG5cdCAgICAgICAgICAgIDB4MWY4MDAwOiAweDQwMTA0MFxuXHQgICAgICAgIH0sXG5cdCAgICAgICAge1xuXHQgICAgICAgICAgICAweDA6IDB4ODAsXG5cdCAgICAgICAgICAgIDB4MTAwMDogMHgxMDQwMDAwLFxuXHQgICAgICAgICAgICAweDIwMDA6IDB4NDAwMDAsXG5cdCAgICAgICAgICAgIDB4MzAwMDogMHgyMDAwMDAwMCxcblx0ICAgICAgICAgICAgMHg0MDAwOiAweDIwMDQwMDgwLFxuXHQgICAgICAgICAgICAweDUwMDA6IDB4MTAwMDA4MCxcblx0ICAgICAgICAgICAgMHg2MDAwOiAweDIxMDAwMDgwLFxuXHQgICAgICAgICAgICAweDcwMDA6IDB4NDAwODAsXG5cdCAgICAgICAgICAgIDB4ODAwMDogMHgxMDAwMDAwLFxuXHQgICAgICAgICAgICAweDkwMDA6IDB4MjAwNDAwMDAsXG5cdCAgICAgICAgICAgIDB4YTAwMDogMHgyMDAwMDA4MCxcblx0ICAgICAgICAgICAgMHhiMDAwOiAweDIxMDQwMDgwLFxuXHQgICAgICAgICAgICAweGMwMDA6IDB4MjEwNDAwMDAsXG5cdCAgICAgICAgICAgIDB4ZDAwMDogMHgwLFxuXHQgICAgICAgICAgICAweGUwMDA6IDB4MTA0MDA4MCxcblx0ICAgICAgICAgICAgMHhmMDAwOiAweDIxMDAwMDAwLFxuXHQgICAgICAgICAgICAweDgwMDogMHgxMDQwMDgwLFxuXHQgICAgICAgICAgICAweDE4MDA6IDB4MjEwMDAwODAsXG5cdCAgICAgICAgICAgIDB4MjgwMDogMHg4MCxcblx0ICAgICAgICAgICAgMHgzODAwOiAweDEwNDAwMDAsXG5cdCAgICAgICAgICAgIDB4NDgwMDogMHg0MDAwMCxcblx0ICAgICAgICAgICAgMHg1ODAwOiAweDIwMDQwMDgwLFxuXHQgICAgICAgICAgICAweDY4MDA6IDB4MjEwNDAwMDAsXG5cdCAgICAgICAgICAgIDB4NzgwMDogMHgyMDAwMDAwMCxcblx0ICAgICAgICAgICAgMHg4ODAwOiAweDIwMDQwMDAwLFxuXHQgICAgICAgICAgICAweDk4MDA6IDB4MCxcblx0ICAgICAgICAgICAgMHhhODAwOiAweDIxMDQwMDgwLFxuXHQgICAgICAgICAgICAweGI4MDA6IDB4MTAwMDA4MCxcblx0ICAgICAgICAgICAgMHhjODAwOiAweDIwMDAwMDgwLFxuXHQgICAgICAgICAgICAweGQ4MDA6IDB4MjEwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4ZTgwMDogMHgxMDAwMDAwLFxuXHQgICAgICAgICAgICAweGY4MDA6IDB4NDAwODAsXG5cdCAgICAgICAgICAgIDB4MTAwMDA6IDB4NDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTEwMDA6IDB4ODAsXG5cdCAgICAgICAgICAgIDB4MTIwMDA6IDB4MjAwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTMwMDA6IDB4MjEwMDAwODAsXG5cdCAgICAgICAgICAgIDB4MTQwMDA6IDB4MTAwMDA4MCxcblx0ICAgICAgICAgICAgMHgxNTAwMDogMHgyMTA0MDAwMCxcblx0ICAgICAgICAgICAgMHgxNjAwMDogMHgyMDA0MDA4MCxcblx0ICAgICAgICAgICAgMHgxNzAwMDogMHgxMDAwMDAwLFxuXHQgICAgICAgICAgICAweDE4MDAwOiAweDIxMDQwMDgwLFxuXHQgICAgICAgICAgICAweDE5MDAwOiAweDIxMDAwMDAwLFxuXHQgICAgICAgICAgICAweDFhMDAwOiAweDEwNDAwMDAsXG5cdCAgICAgICAgICAgIDB4MWIwMDA6IDB4MjAwNDAwMDAsXG5cdCAgICAgICAgICAgIDB4MWMwMDA6IDB4NDAwODAsXG5cdCAgICAgICAgICAgIDB4MWQwMDA6IDB4MjAwMDAwODAsXG5cdCAgICAgICAgICAgIDB4MWUwMDA6IDB4MCxcblx0ICAgICAgICAgICAgMHgxZjAwMDogMHgxMDQwMDgwLFxuXHQgICAgICAgICAgICAweDEwODAwOiAweDIxMDAwMDgwLFxuXHQgICAgICAgICAgICAweDExODAwOiAweDEwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTI4MDA6IDB4MTA0MDAwMCxcblx0ICAgICAgICAgICAgMHgxMzgwMDogMHgyMDA0MDA4MCxcblx0ICAgICAgICAgICAgMHgxNDgwMDogMHgyMDAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxNTgwMDogMHgxMDQwMDgwLFxuXHQgICAgICAgICAgICAweDE2ODAwOiAweDgwLFxuXHQgICAgICAgICAgICAweDE3ODAwOiAweDIxMDQwMDAwLFxuXHQgICAgICAgICAgICAweDE4ODAwOiAweDQwMDgwLFxuXHQgICAgICAgICAgICAweDE5ODAwOiAweDIxMDQwMDgwLFxuXHQgICAgICAgICAgICAweDFhODAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MWI4MDA6IDB4MjEwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MWM4MDA6IDB4MTAwMDA4MCxcblx0ICAgICAgICAgICAgMHgxZDgwMDogMHg0MDAwMCxcblx0ICAgICAgICAgICAgMHgxZTgwMDogMHgyMDA0MDAwMCxcblx0ICAgICAgICAgICAgMHgxZjgwMDogMHgyMDAwMDA4MFxuXHQgICAgICAgIH0sXG5cdCAgICAgICAge1xuXHQgICAgICAgICAgICAweDA6IDB4MTAwMDAwMDgsXG5cdCAgICAgICAgICAgIDB4MTAwOiAweDIwMDAsXG5cdCAgICAgICAgICAgIDB4MjAwOiAweDEwMjAwMDAwLFxuXHQgICAgICAgICAgICAweDMwMDogMHgxMDIwMjAwOCxcblx0ICAgICAgICAgICAgMHg0MDA6IDB4MTAwMDIwMDAsXG5cdCAgICAgICAgICAgIDB4NTAwOiAweDIwMDAwMCxcblx0ICAgICAgICAgICAgMHg2MDA6IDB4MjAwMDA4LFxuXHQgICAgICAgICAgICAweDcwMDogMHgxMDAwMDAwMCxcblx0ICAgICAgICAgICAgMHg4MDA6IDB4MCxcblx0ICAgICAgICAgICAgMHg5MDA6IDB4MTAwMDIwMDgsXG5cdCAgICAgICAgICAgIDB4YTAwOiAweDIwMjAwMCxcblx0ICAgICAgICAgICAgMHhiMDA6IDB4OCxcblx0ICAgICAgICAgICAgMHhjMDA6IDB4MTAyMDAwMDgsXG5cdCAgICAgICAgICAgIDB4ZDAwOiAweDIwMjAwOCxcblx0ICAgICAgICAgICAgMHhlMDA6IDB4MjAwOCxcblx0ICAgICAgICAgICAgMHhmMDA6IDB4MTAyMDIwMDAsXG5cdCAgICAgICAgICAgIDB4ODA6IDB4MTAyMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTgwOiAweDEwMjAyMDA4LFxuXHQgICAgICAgICAgICAweDI4MDogMHg4LFxuXHQgICAgICAgICAgICAweDM4MDogMHgyMDAwMDAsXG5cdCAgICAgICAgICAgIDB4NDgwOiAweDIwMjAwOCxcblx0ICAgICAgICAgICAgMHg1ODA6IDB4MTAwMDAwMDgsXG5cdCAgICAgICAgICAgIDB4NjgwOiAweDEwMDAyMDAwLFxuXHQgICAgICAgICAgICAweDc4MDogMHgyMDA4LFxuXHQgICAgICAgICAgICAweDg4MDogMHgyMDAwMDgsXG5cdCAgICAgICAgICAgIDB4OTgwOiAweDIwMDAsXG5cdCAgICAgICAgICAgIDB4YTgwOiAweDEwMDAyMDA4LFxuXHQgICAgICAgICAgICAweGI4MDogMHgxMDIwMDAwOCxcblx0ICAgICAgICAgICAgMHhjODA6IDB4MCxcblx0ICAgICAgICAgICAgMHhkODA6IDB4MTAyMDIwMDAsXG5cdCAgICAgICAgICAgIDB4ZTgwOiAweDIwMjAwMCxcblx0ICAgICAgICAgICAgMHhmODA6IDB4MTAwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTAwMDogMHgxMDAwMjAwMCxcblx0ICAgICAgICAgICAgMHgxMTAwOiAweDEwMjAwMDA4LFxuXHQgICAgICAgICAgICAweDEyMDA6IDB4MTAyMDIwMDgsXG5cdCAgICAgICAgICAgIDB4MTMwMDogMHgyMDA4LFxuXHQgICAgICAgICAgICAweDE0MDA6IDB4MjAwMDAwLFxuXHQgICAgICAgICAgICAweDE1MDA6IDB4MTAwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTYwMDogMHgxMDAwMDAwOCxcblx0ICAgICAgICAgICAgMHgxNzAwOiAweDIwMjAwMCxcblx0ICAgICAgICAgICAgMHgxODAwOiAweDIwMjAwOCxcblx0ICAgICAgICAgICAgMHgxOTAwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MWEwMDogMHg4LFxuXHQgICAgICAgICAgICAweDFiMDA6IDB4MTAyMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MWMwMDogMHgyMDAwLFxuXHQgICAgICAgICAgICAweDFkMDA6IDB4MTAwMDIwMDgsXG5cdCAgICAgICAgICAgIDB4MWUwMDogMHgxMDIwMjAwMCxcblx0ICAgICAgICAgICAgMHgxZjAwOiAweDIwMDAwOCxcblx0ICAgICAgICAgICAgMHgxMDgwOiAweDgsXG5cdCAgICAgICAgICAgIDB4MTE4MDogMHgyMDIwMDAsXG5cdCAgICAgICAgICAgIDB4MTI4MDogMHgyMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTM4MDogMHgxMDAwMDAwOCxcblx0ICAgICAgICAgICAgMHgxNDgwOiAweDEwMDAyMDAwLFxuXHQgICAgICAgICAgICAweDE1ODA6IDB4MjAwOCxcblx0ICAgICAgICAgICAgMHgxNjgwOiAweDEwMjAyMDA4LFxuXHQgICAgICAgICAgICAweDE3ODA6IDB4MTAyMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTg4MDogMHgxMDIwMjAwMCxcblx0ICAgICAgICAgICAgMHgxOTgwOiAweDEwMjAwMDA4LFxuXHQgICAgICAgICAgICAweDFhODA6IDB4MjAwMCxcblx0ICAgICAgICAgICAgMHgxYjgwOiAweDIwMjAwOCxcblx0ICAgICAgICAgICAgMHgxYzgwOiAweDIwMDAwOCxcblx0ICAgICAgICAgICAgMHgxZDgwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MWU4MDogMHgxMDAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxZjgwOiAweDEwMDAyMDA4XG5cdCAgICAgICAgfSxcblx0ICAgICAgICB7XG5cdCAgICAgICAgICAgIDB4MDogMHgxMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTA6IDB4MjAwMDQwMSxcblx0ICAgICAgICAgICAgMHgyMDogMHg0MDAsXG5cdCAgICAgICAgICAgIDB4MzA6IDB4MTAwNDAxLFxuXHQgICAgICAgICAgICAweDQwOiAweDIxMDA0MDEsXG5cdCAgICAgICAgICAgIDB4NTA6IDB4MCxcblx0ICAgICAgICAgICAgMHg2MDogMHgxLFxuXHQgICAgICAgICAgICAweDcwOiAweDIxMDAwMDEsXG5cdCAgICAgICAgICAgIDB4ODA6IDB4MjAwMDQwMCxcblx0ICAgICAgICAgICAgMHg5MDogMHgxMDAwMDEsXG5cdCAgICAgICAgICAgIDB4YTA6IDB4MjAwMDAwMSxcblx0ICAgICAgICAgICAgMHhiMDogMHgyMTAwNDAwLFxuXHQgICAgICAgICAgICAweGMwOiAweDIxMDAwMDAsXG5cdCAgICAgICAgICAgIDB4ZDA6IDB4NDAxLFxuXHQgICAgICAgICAgICAweGUwOiAweDEwMDQwMCxcblx0ICAgICAgICAgICAgMHhmMDogMHgyMDAwMDAwLFxuXHQgICAgICAgICAgICAweDg6IDB4MjEwMDAwMSxcblx0ICAgICAgICAgICAgMHgxODogMHgwLFxuXHQgICAgICAgICAgICAweDI4OiAweDIwMDA0MDEsXG5cdCAgICAgICAgICAgIDB4Mzg6IDB4MjEwMDQwMCxcblx0ICAgICAgICAgICAgMHg0ODogMHgxMDAwMDAsXG5cdCAgICAgICAgICAgIDB4NTg6IDB4MjAwMDAwMSxcblx0ICAgICAgICAgICAgMHg2ODogMHgyMDAwMDAwLFxuXHQgICAgICAgICAgICAweDc4OiAweDQwMSxcblx0ICAgICAgICAgICAgMHg4ODogMHgxMDA0MDEsXG5cdCAgICAgICAgICAgIDB4OTg6IDB4MjAwMDQwMCxcblx0ICAgICAgICAgICAgMHhhODogMHgyMTAwMDAwLFxuXHQgICAgICAgICAgICAweGI4OiAweDEwMDAwMSxcblx0ICAgICAgICAgICAgMHhjODogMHg0MDAsXG5cdCAgICAgICAgICAgIDB4ZDg6IDB4MjEwMDQwMSxcblx0ICAgICAgICAgICAgMHhlODogMHgxLFxuXHQgICAgICAgICAgICAweGY4OiAweDEwMDQwMCxcblx0ICAgICAgICAgICAgMHgxMDA6IDB4MjAwMDAwMCxcblx0ICAgICAgICAgICAgMHgxMTA6IDB4MTAwMDAwLFxuXHQgICAgICAgICAgICAweDEyMDogMHgyMDAwNDAxLFxuXHQgICAgICAgICAgICAweDEzMDogMHgyMTAwMDAxLFxuXHQgICAgICAgICAgICAweDE0MDogMHgxMDAwMDEsXG5cdCAgICAgICAgICAgIDB4MTUwOiAweDIwMDA0MDAsXG5cdCAgICAgICAgICAgIDB4MTYwOiAweDIxMDA0MDAsXG5cdCAgICAgICAgICAgIDB4MTcwOiAweDEwMDQwMSxcblx0ICAgICAgICAgICAgMHgxODA6IDB4NDAxLFxuXHQgICAgICAgICAgICAweDE5MDogMHgyMTAwNDAxLFxuXHQgICAgICAgICAgICAweDFhMDogMHgxMDA0MDAsXG5cdCAgICAgICAgICAgIDB4MWIwOiAweDEsXG5cdCAgICAgICAgICAgIDB4MWMwOiAweDAsXG5cdCAgICAgICAgICAgIDB4MWQwOiAweDIxMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MWUwOiAweDIwMDAwMDEsXG5cdCAgICAgICAgICAgIDB4MWYwOiAweDQwMCxcblx0ICAgICAgICAgICAgMHgxMDg6IDB4MTAwNDAwLFxuXHQgICAgICAgICAgICAweDExODogMHgyMDAwNDAxLFxuXHQgICAgICAgICAgICAweDEyODogMHgyMTAwMDAxLFxuXHQgICAgICAgICAgICAweDEzODogMHgxLFxuXHQgICAgICAgICAgICAweDE0ODogMHgyMDAwMDAwLFxuXHQgICAgICAgICAgICAweDE1ODogMHgxMDAwMDAsXG5cdCAgICAgICAgICAgIDB4MTY4OiAweDQwMSxcblx0ICAgICAgICAgICAgMHgxNzg6IDB4MjEwMDQwMCxcblx0ICAgICAgICAgICAgMHgxODg6IDB4MjAwMDAwMSxcblx0ICAgICAgICAgICAgMHgxOTg6IDB4MjEwMDAwMCxcblx0ICAgICAgICAgICAgMHgxYTg6IDB4MCxcblx0ICAgICAgICAgICAgMHgxYjg6IDB4MjEwMDQwMSxcblx0ICAgICAgICAgICAgMHgxYzg6IDB4MTAwNDAxLFxuXHQgICAgICAgICAgICAweDFkODogMHg0MDAsXG5cdCAgICAgICAgICAgIDB4MWU4OiAweDIwMDA0MDAsXG5cdCAgICAgICAgICAgIDB4MWY4OiAweDEwMDAwMVxuXHQgICAgICAgIH0sXG5cdCAgICAgICAge1xuXHQgICAgICAgICAgICAweDA6IDB4ODAwMDgyMCxcblx0ICAgICAgICAgICAgMHgxOiAweDIwMDAwLFxuXHQgICAgICAgICAgICAweDI6IDB4ODAwMDAwMCxcblx0ICAgICAgICAgICAgMHgzOiAweDIwLFxuXHQgICAgICAgICAgICAweDQ6IDB4MjAwMjAsXG5cdCAgICAgICAgICAgIDB4NTogMHg4MDIwODIwLFxuXHQgICAgICAgICAgICAweDY6IDB4ODAyMDgwMCxcblx0ICAgICAgICAgICAgMHg3OiAweDgwMCxcblx0ICAgICAgICAgICAgMHg4OiAweDgwMjAwMDAsXG5cdCAgICAgICAgICAgIDB4OTogMHg4MDAwODAwLFxuXHQgICAgICAgICAgICAweGE6IDB4MjA4MDAsXG5cdCAgICAgICAgICAgIDB4YjogMHg4MDIwMDIwLFxuXHQgICAgICAgICAgICAweGM6IDB4ODIwLFxuXHQgICAgICAgICAgICAweGQ6IDB4MCxcblx0ICAgICAgICAgICAgMHhlOiAweDgwMDAwMjAsXG5cdCAgICAgICAgICAgIDB4ZjogMHgyMDgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwMDogMHg4MDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMDE6IDB4ODAyMDgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwMjogMHg4MDAwODIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDAzOiAweDgwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMDQ6IDB4ODAyMDAwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwNTogMHgyMDgwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwNjogMHgyMDgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwNzogMHgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwODogMHg4MDAwMDIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDA5OiAweDgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwYTogMHgyMDAyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwYjogMHg4MDIwODAwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDBjOiAweDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMGQ6IDB4ODAyMDAyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAwZTogMHg4MDAwODAwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDBmOiAweDIwMDAwLFxuXHQgICAgICAgICAgICAweDEwOiAweDIwODIwLFxuXHQgICAgICAgICAgICAweDExOiAweDgwMjA4MDAsXG5cdCAgICAgICAgICAgIDB4MTI6IDB4MjAsXG5cdCAgICAgICAgICAgIDB4MTM6IDB4ODAwLFxuXHQgICAgICAgICAgICAweDE0OiAweDgwMDA4MDAsXG5cdCAgICAgICAgICAgIDB4MTU6IDB4ODAwMDAyMCxcblx0ICAgICAgICAgICAgMHgxNjogMHg4MDIwMDIwLFxuXHQgICAgICAgICAgICAweDE3OiAweDIwMDAwLFxuXHQgICAgICAgICAgICAweDE4OiAweDAsXG5cdCAgICAgICAgICAgIDB4MTk6IDB4MjAwMjAsXG5cdCAgICAgICAgICAgIDB4MWE6IDB4ODAyMDAwMCxcblx0ICAgICAgICAgICAgMHgxYjogMHg4MDAwODIwLFxuXHQgICAgICAgICAgICAweDFjOiAweDgwMjA4MjAsXG5cdCAgICAgICAgICAgIDB4MWQ6IDB4MjA4MDAsXG5cdCAgICAgICAgICAgIDB4MWU6IDB4ODIwLFxuXHQgICAgICAgICAgICAweDFmOiAweDgwMDAwMDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMTA6IDB4MjAwMDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMTE6IDB4ODAwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDEyOiAweDgwMjAwMjAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMTM6IDB4MjA4MjAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMTQ6IDB4MjAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMTU6IDB4ODAyMDAwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxNjogMHg4MDAwMDAwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDE3OiAweDgwMDA4MjAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMTg6IDB4ODAyMDgyMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxOTogMHg4MDAwMDIwLFxuXHQgICAgICAgICAgICAweDgwMDAwMDFhOiAweDgwMDA4MDAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMWI6IDB4MCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxYzogMHgyMDgwMCxcblx0ICAgICAgICAgICAgMHg4MDAwMDAxZDogMHg4MjAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMWU6IDB4MjAwMjAsXG5cdCAgICAgICAgICAgIDB4ODAwMDAwMWY6IDB4ODAyMDgwMFxuXHQgICAgICAgIH1cblx0ICAgIF07XG5cblx0ICAgIC8vIE1hc2tzIHRoYXQgc2VsZWN0IHRoZSBTQk9YIGlucHV0XG5cdCAgICB2YXIgU0JPWF9NQVNLID0gW1xuXHQgICAgICAgIDB4ZjgwMDAwMDEsIDB4MWY4MDAwMDAsIDB4MDFmODAwMDAsIDB4MDAxZjgwMDAsXG5cdCAgICAgICAgMHgwMDAxZjgwMCwgMHgwMDAwMWY4MCwgMHgwMDAwMDFmOCwgMHg4MDAwMDAxZlxuXHQgICAgXTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBERVMgYmxvY2sgY2lwaGVyIGFsZ29yaXRobS5cblx0ICAgICAqL1xuXHQgICAgdmFyIERFUyA9IENfYWxnby5ERVMgPSBCbG9ja0NpcGhlci5leHRlbmQoe1xuXHQgICAgICAgIF9kb1Jlc2V0OiBmdW5jdGlvbiAoKSB7XG5cdCAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICB2YXIga2V5ID0gdGhpcy5fa2V5O1xuXHQgICAgICAgICAgICB2YXIga2V5V29yZHMgPSBrZXkud29yZHM7XG5cblx0ICAgICAgICAgICAgLy8gU2VsZWN0IDU2IGJpdHMgYWNjb3JkaW5nIHRvIFBDMVxuXHQgICAgICAgICAgICB2YXIga2V5Qml0cyA9IFtdO1xuXHQgICAgICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDU2OyBpKyspIHtcblx0ICAgICAgICAgICAgICAgIHZhciBrZXlCaXRQb3MgPSBQQzFbaV0gLSAxO1xuXHQgICAgICAgICAgICAgICAga2V5Qml0c1tpXSA9IChrZXlXb3Jkc1trZXlCaXRQb3MgPj4+IDVdID4+PiAoMzEgLSBrZXlCaXRQb3MgJSAzMikpICYgMTtcblx0ICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgIC8vIEFzc2VtYmxlIDE2IHN1YmtleXNcblx0ICAgICAgICAgICAgdmFyIHN1YktleXMgPSB0aGlzLl9zdWJLZXlzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIG5TdWJLZXkgPSAwOyBuU3ViS2V5IDwgMTY7IG5TdWJLZXkrKykge1xuXHQgICAgICAgICAgICAgICAgLy8gQ3JlYXRlIHN1YmtleVxuXHQgICAgICAgICAgICAgICAgdmFyIHN1YktleSA9IHN1YktleXNbblN1YktleV0gPSBbXTtcblxuXHQgICAgICAgICAgICAgICAgLy8gU2hvcnRjdXRcblx0ICAgICAgICAgICAgICAgIHZhciBiaXRTaGlmdCA9IEJJVF9TSElGVFNbblN1YktleV07XG5cblx0ICAgICAgICAgICAgICAgIC8vIFNlbGVjdCA0OCBiaXRzIGFjY29yZGluZyB0byBQQzJcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMjQ7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgICAgIC8vIFNlbGVjdCBmcm9tIHRoZSBsZWZ0IDI4IGtleSBiaXRzXG5cdCAgICAgICAgICAgICAgICAgICAgc3ViS2V5WyhpIC8gNikgfCAwXSB8PSBrZXlCaXRzWygoUEMyW2ldIC0gMSkgKyBiaXRTaGlmdCkgJSAyOF0gPDwgKDMxIC0gaSAlIDYpO1xuXG5cdCAgICAgICAgICAgICAgICAgICAgLy8gU2VsZWN0IGZyb20gdGhlIHJpZ2h0IDI4IGtleSBiaXRzXG5cdCAgICAgICAgICAgICAgICAgICAgc3ViS2V5WzQgKyAoKGkgLyA2KSB8IDApXSB8PSBrZXlCaXRzWzI4ICsgKCgoUEMyW2kgKyAyNF0gLSAxKSArIGJpdFNoaWZ0KSAlIDI4KV0gPDwgKDMxIC0gaSAlIDYpO1xuXHQgICAgICAgICAgICAgICAgfVxuXG5cdCAgICAgICAgICAgICAgICAvLyBTaW5jZSBlYWNoIHN1YmtleSBpcyBhcHBsaWVkIHRvIGFuIGV4cGFuZGVkIDMyLWJpdCBpbnB1dCxcblx0ICAgICAgICAgICAgICAgIC8vIHRoZSBzdWJrZXkgY2FuIGJlIGJyb2tlbiBpbnRvIDggdmFsdWVzIHNjYWxlZCB0byAzMi1iaXRzLFxuXHQgICAgICAgICAgICAgICAgLy8gd2hpY2ggYWxsb3dzIHRoZSBrZXkgdG8gYmUgdXNlZCB3aXRob3V0IGV4cGFuc2lvblxuXHQgICAgICAgICAgICAgICAgc3ViS2V5WzBdID0gKHN1YktleVswXSA8PCAxKSB8IChzdWJLZXlbMF0gPj4+IDMxKTtcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAxOyBpIDwgNzsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgc3ViS2V5W2ldID0gc3ViS2V5W2ldID4+PiAoKGkgLSAxKSAqIDQgKyAzKTtcblx0ICAgICAgICAgICAgICAgIH1cblx0ICAgICAgICAgICAgICAgIHN1YktleVs3XSA9IChzdWJLZXlbN10gPDwgNSkgfCAoc3ViS2V5WzddID4+PiAyNyk7XG5cdCAgICAgICAgICAgIH1cblxuXHQgICAgICAgICAgICAvLyBDb21wdXRlIGludmVyc2Ugc3Via2V5c1xuXHQgICAgICAgICAgICB2YXIgaW52U3ViS2V5cyA9IHRoaXMuX2ludlN1YktleXMgPSBbXTtcblx0ICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCAxNjsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICBpbnZTdWJLZXlzW2ldID0gc3ViS2V5c1sxNSAtIGldO1xuXHQgICAgICAgICAgICB9XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGVuY3J5cHRCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICB0aGlzLl9kb0NyeXB0QmxvY2soTSwgb2Zmc2V0LCB0aGlzLl9zdWJLZXlzKTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAgZGVjcnlwdEJsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0KSB7XG5cdCAgICAgICAgICAgIHRoaXMuX2RvQ3J5cHRCbG9jayhNLCBvZmZzZXQsIHRoaXMuX2ludlN1YktleXMpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBfZG9DcnlwdEJsb2NrOiBmdW5jdGlvbiAoTSwgb2Zmc2V0LCBzdWJLZXlzKSB7XG5cdCAgICAgICAgICAgIC8vIEdldCBpbnB1dFxuXHQgICAgICAgICAgICB0aGlzLl9sQmxvY2sgPSBNW29mZnNldF07XG5cdCAgICAgICAgICAgIHRoaXMuX3JCbG9jayA9IE1bb2Zmc2V0ICsgMV07XG5cblx0ICAgICAgICAgICAgLy8gSW5pdGlhbCBwZXJtdXRhdGlvblxuXHQgICAgICAgICAgICBleGNoYW5nZUxSLmNhbGwodGhpcywgNCwgIDB4MGYwZjBmMGYpO1xuXHQgICAgICAgICAgICBleGNoYW5nZUxSLmNhbGwodGhpcywgMTYsIDB4MDAwMGZmZmYpO1xuXHQgICAgICAgICAgICBleGNoYW5nZVJMLmNhbGwodGhpcywgMiwgIDB4MzMzMzMzMzMpO1xuXHQgICAgICAgICAgICBleGNoYW5nZVJMLmNhbGwodGhpcywgOCwgIDB4MDBmZjAwZmYpO1xuXHQgICAgICAgICAgICBleGNoYW5nZUxSLmNhbGwodGhpcywgMSwgIDB4NTU1NTU1NTUpO1xuXG5cdCAgICAgICAgICAgIC8vIFJvdW5kc1xuXHQgICAgICAgICAgICBmb3IgKHZhciByb3VuZCA9IDA7IHJvdW5kIDwgMTY7IHJvdW5kKyspIHtcblx0ICAgICAgICAgICAgICAgIC8vIFNob3J0Y3V0c1xuXHQgICAgICAgICAgICAgICAgdmFyIHN1YktleSA9IHN1YktleXNbcm91bmRdO1xuXHQgICAgICAgICAgICAgICAgdmFyIGxCbG9jayA9IHRoaXMuX2xCbG9jaztcblx0ICAgICAgICAgICAgICAgIHZhciByQmxvY2sgPSB0aGlzLl9yQmxvY2s7XG5cblx0ICAgICAgICAgICAgICAgIC8vIEZlaXN0ZWwgZnVuY3Rpb25cblx0ICAgICAgICAgICAgICAgIHZhciBmID0gMDtcblx0ICAgICAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgODsgaSsrKSB7XG5cdCAgICAgICAgICAgICAgICAgICAgZiB8PSBTQk9YX1BbaV1bKChyQmxvY2sgXiBzdWJLZXlbaV0pICYgU0JPWF9NQVNLW2ldKSA+Pj4gMF07XG5cdCAgICAgICAgICAgICAgICB9XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9sQmxvY2sgPSByQmxvY2s7XG5cdCAgICAgICAgICAgICAgICB0aGlzLl9yQmxvY2sgPSBsQmxvY2sgXiBmO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgLy8gVW5kbyBzd2FwIGZyb20gbGFzdCByb3VuZFxuXHQgICAgICAgICAgICB2YXIgdCA9IHRoaXMuX2xCbG9jaztcblx0ICAgICAgICAgICAgdGhpcy5fbEJsb2NrID0gdGhpcy5fckJsb2NrO1xuXHQgICAgICAgICAgICB0aGlzLl9yQmxvY2sgPSB0O1xuXG5cdCAgICAgICAgICAgIC8vIEZpbmFsIHBlcm11dGF0aW9uXG5cdCAgICAgICAgICAgIGV4Y2hhbmdlTFIuY2FsbCh0aGlzLCAxLCAgMHg1NTU1NTU1NSk7XG5cdCAgICAgICAgICAgIGV4Y2hhbmdlUkwuY2FsbCh0aGlzLCA4LCAgMHgwMGZmMDBmZik7XG5cdCAgICAgICAgICAgIGV4Y2hhbmdlUkwuY2FsbCh0aGlzLCAyLCAgMHgzMzMzMzMzMyk7XG5cdCAgICAgICAgICAgIGV4Y2hhbmdlTFIuY2FsbCh0aGlzLCAxNiwgMHgwMDAwZmZmZik7XG5cdCAgICAgICAgICAgIGV4Y2hhbmdlTFIuY2FsbCh0aGlzLCA0LCAgMHgwZjBmMGYwZik7XG5cblx0ICAgICAgICAgICAgLy8gU2V0IG91dHB1dFxuXHQgICAgICAgICAgICBNW29mZnNldF0gPSB0aGlzLl9sQmxvY2s7XG5cdCAgICAgICAgICAgIE1bb2Zmc2V0ICsgMV0gPSB0aGlzLl9yQmxvY2s7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGtleVNpemU6IDY0LzMyLFxuXG5cdCAgICAgICAgaXZTaXplOiA2NC8zMixcblxuXHQgICAgICAgIGJsb2NrU2l6ZTogNjQvMzJcblx0ICAgIH0pO1xuXG5cdCAgICAvLyBTd2FwIGJpdHMgYWNyb3NzIHRoZSBsZWZ0IGFuZCByaWdodCB3b3Jkc1xuXHQgICAgZnVuY3Rpb24gZXhjaGFuZ2VMUihvZmZzZXQsIG1hc2spIHtcblx0ICAgICAgICB2YXIgdCA9ICgodGhpcy5fbEJsb2NrID4+PiBvZmZzZXQpIF4gdGhpcy5fckJsb2NrKSAmIG1hc2s7XG5cdCAgICAgICAgdGhpcy5fckJsb2NrIF49IHQ7XG5cdCAgICAgICAgdGhpcy5fbEJsb2NrIF49IHQgPDwgb2Zmc2V0O1xuXHQgICAgfVxuXG5cdCAgICBmdW5jdGlvbiBleGNoYW5nZVJMKG9mZnNldCwgbWFzaykge1xuXHQgICAgICAgIHZhciB0ID0gKCh0aGlzLl9yQmxvY2sgPj4+IG9mZnNldCkgXiB0aGlzLl9sQmxvY2spICYgbWFzaztcblx0ICAgICAgICB0aGlzLl9sQmxvY2sgXj0gdDtcblx0ICAgICAgICB0aGlzLl9yQmxvY2sgXj0gdCA8PCBvZmZzZXQ7XG5cdCAgICB9XG5cblx0ICAgIC8qKlxuXHQgICAgICogU2hvcnRjdXQgZnVuY3Rpb25zIHRvIHRoZSBjaXBoZXIncyBvYmplY3QgaW50ZXJmYWNlLlxuXHQgICAgICpcblx0ICAgICAqIEBleGFtcGxlXG5cdCAgICAgKlxuXHQgICAgICogICAgIHZhciBjaXBoZXJ0ZXh0ID0gQ3J5cHRvSlMuREVTLmVuY3J5cHQobWVzc2FnZSwga2V5LCBjZmcpO1xuXHQgICAgICogICAgIHZhciBwbGFpbnRleHQgID0gQ3J5cHRvSlMuREVTLmRlY3J5cHQoY2lwaGVydGV4dCwga2V5LCBjZmcpO1xuXHQgICAgICovXG5cdCAgICBDLkRFUyA9IEJsb2NrQ2lwaGVyLl9jcmVhdGVIZWxwZXIoREVTKTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBUcmlwbGUtREVTIGJsb2NrIGNpcGhlciBhbGdvcml0aG0uXG5cdCAgICAgKi9cblx0ICAgIHZhciBUcmlwbGVERVMgPSBDX2FsZ28uVHJpcGxlREVTID0gQmxvY2tDaXBoZXIuZXh0ZW5kKHtcblx0ICAgICAgICBfZG9SZXNldDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIGtleSA9IHRoaXMuX2tleTtcblx0ICAgICAgICAgICAgdmFyIGtleVdvcmRzID0ga2V5LndvcmRzO1xuXG5cdCAgICAgICAgICAgIC8vIENyZWF0ZSBERVMgaW5zdGFuY2VzXG5cdCAgICAgICAgICAgIHRoaXMuX2RlczEgPSBERVMuY3JlYXRlRW5jcnlwdG9yKFdvcmRBcnJheS5jcmVhdGUoa2V5V29yZHMuc2xpY2UoMCwgMikpKTtcblx0ICAgICAgICAgICAgdGhpcy5fZGVzMiA9IERFUy5jcmVhdGVFbmNyeXB0b3IoV29yZEFycmF5LmNyZWF0ZShrZXlXb3Jkcy5zbGljZSgyLCA0KSkpO1xuXHQgICAgICAgICAgICB0aGlzLl9kZXMzID0gREVTLmNyZWF0ZUVuY3J5cHRvcihXb3JkQXJyYXkuY3JlYXRlKGtleVdvcmRzLnNsaWNlKDQsIDYpKSk7XG5cdCAgICAgICAgfSxcblxuXHQgICAgICAgIGVuY3J5cHRCbG9jazogZnVuY3Rpb24gKE0sIG9mZnNldCkge1xuXHQgICAgICAgICAgICB0aGlzLl9kZXMxLmVuY3J5cHRCbG9jayhNLCBvZmZzZXQpO1xuXHQgICAgICAgICAgICB0aGlzLl9kZXMyLmRlY3J5cHRCbG9jayhNLCBvZmZzZXQpO1xuXHQgICAgICAgICAgICB0aGlzLl9kZXMzLmVuY3J5cHRCbG9jayhNLCBvZmZzZXQpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICBkZWNyeXB0QmxvY2s6IGZ1bmN0aW9uIChNLCBvZmZzZXQpIHtcblx0ICAgICAgICAgICAgdGhpcy5fZGVzMy5kZWNyeXB0QmxvY2soTSwgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgdGhpcy5fZGVzMi5lbmNyeXB0QmxvY2soTSwgb2Zmc2V0KTtcblx0ICAgICAgICAgICAgdGhpcy5fZGVzMS5kZWNyeXB0QmxvY2soTSwgb2Zmc2V0KTtcblx0ICAgICAgICB9LFxuXG5cdCAgICAgICAga2V5U2l6ZTogMTkyLzMyLFxuXG5cdCAgICAgICAgaXZTaXplOiA2NC8zMixcblxuXHQgICAgICAgIGJsb2NrU2l6ZTogNjQvMzJcblx0ICAgIH0pO1xuXG5cdCAgICAvKipcblx0ICAgICAqIFNob3J0Y3V0IGZ1bmN0aW9ucyB0byB0aGUgY2lwaGVyJ3Mgb2JqZWN0IGludGVyZmFjZS5cblx0ICAgICAqXG5cdCAgICAgKiBAZXhhbXBsZVxuXHQgICAgICpcblx0ICAgICAqICAgICB2YXIgY2lwaGVydGV4dCA9IENyeXB0b0pTLlRyaXBsZURFUy5lbmNyeXB0KG1lc3NhZ2UsIGtleSwgY2ZnKTtcblx0ICAgICAqICAgICB2YXIgcGxhaW50ZXh0ICA9IENyeXB0b0pTLlRyaXBsZURFUy5kZWNyeXB0KGNpcGhlcnRleHQsIGtleSwgY2ZnKTtcblx0ICAgICAqL1xuXHQgICAgQy5UcmlwbGVERVMgPSBCbG9ja0NpcGhlci5fY3JlYXRlSGVscGVyKFRyaXBsZURFUyk7XG5cdH0oKSk7XG5cblxuXHRyZXR1cm4gQ3J5cHRvSlMuVHJpcGxlREVTO1xuXG59KSk7IiwiOyhmdW5jdGlvbiAocm9vdCwgZmFjdG9yeSkge1xuXHRpZiAodHlwZW9mIGV4cG9ydHMgPT09IFwib2JqZWN0XCIpIHtcblx0XHQvLyBDb21tb25KU1xuXHRcdG1vZHVsZS5leHBvcnRzID0gZXhwb3J0cyA9IGZhY3RvcnkocmVxdWlyZShcIi4vY29yZVwiKSk7XG5cdH1cblx0ZWxzZSBpZiAodHlwZW9mIGRlZmluZSA9PT0gXCJmdW5jdGlvblwiICYmIGRlZmluZS5hbWQpIHtcblx0XHQvLyBBTURcblx0XHRkZWZpbmUoW1wiLi9jb3JlXCJdLCBmYWN0b3J5KTtcblx0fVxuXHRlbHNlIHtcblx0XHQvLyBHbG9iYWwgKGJyb3dzZXIpXG5cdFx0ZmFjdG9yeShyb290LkNyeXB0b0pTKTtcblx0fVxufSh0aGlzLCBmdW5jdGlvbiAoQ3J5cHRvSlMpIHtcblxuXHQoZnVuY3Rpb24gKHVuZGVmaW5lZCkge1xuXHQgICAgLy8gU2hvcnRjdXRzXG5cdCAgICB2YXIgQyA9IENyeXB0b0pTO1xuXHQgICAgdmFyIENfbGliID0gQy5saWI7XG5cdCAgICB2YXIgQmFzZSA9IENfbGliLkJhc2U7XG5cdCAgICB2YXIgWDMyV29yZEFycmF5ID0gQ19saWIuV29yZEFycmF5O1xuXG5cdCAgICAvKipcblx0ICAgICAqIHg2NCBuYW1lc3BhY2UuXG5cdCAgICAgKi9cblx0ICAgIHZhciBDX3g2NCA9IEMueDY0ID0ge307XG5cblx0ICAgIC8qKlxuXHQgICAgICogQSA2NC1iaXQgd29yZC5cblx0ICAgICAqL1xuXHQgICAgdmFyIFg2NFdvcmQgPSBDX3g2NC5Xb3JkID0gQmFzZS5leHRlbmQoe1xuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEluaXRpYWxpemVzIGEgbmV3bHkgY3JlYXRlZCA2NC1iaXQgd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBoaWdoIFRoZSBoaWdoIDMyIGJpdHMuXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IGxvdyBUaGUgbG93IDMyIGJpdHMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB4NjRXb3JkID0gQ3J5cHRvSlMueDY0LldvcmQuY3JlYXRlKDB4MDAwMTAyMDMsIDB4MDQwNTA2MDcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIGluaXQ6IGZ1bmN0aW9uIChoaWdoLCBsb3cpIHtcblx0ICAgICAgICAgICAgdGhpcy5oaWdoID0gaGlnaDtcblx0ICAgICAgICAgICAgdGhpcy5sb3cgPSBsb3c7XG5cdCAgICAgICAgfVxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQml0d2lzZSBOT1RzIHRoaXMgd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1g2NFdvcmR9IEEgbmV3IHg2NC1Xb3JkIG9iamVjdCBhZnRlciBuZWdhdGluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIG5lZ2F0ZWQgPSB4NjRXb3JkLm5vdCgpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIC8vIG5vdDogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyB2YXIgaGlnaCA9IH50aGlzLmhpZ2g7XG5cdCAgICAgICAgICAgIC8vIHZhciBsb3cgPSB+dGhpcy5sb3c7XG5cblx0ICAgICAgICAgICAgLy8gcmV0dXJuIFg2NFdvcmQuY3JlYXRlKGhpZ2gsIGxvdyk7XG5cdCAgICAgICAgLy8gfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIEJpdHdpc2UgQU5EcyB0aGlzIHdvcmQgd2l0aCB0aGUgcGFzc2VkIHdvcmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1g2NFdvcmR9IHdvcmQgVGhlIHg2NC1Xb3JkIHRvIEFORCB3aXRoIHRoaXMgd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1g2NFdvcmR9IEEgbmV3IHg2NC1Xb3JkIG9iamVjdCBhZnRlciBBTkRpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBhbmRlZCA9IHg2NFdvcmQuYW5kKGFub3RoZXJYNjRXb3JkKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICAvLyBhbmQ6IGZ1bmN0aW9uICh3b3JkKSB7XG5cdCAgICAgICAgICAgIC8vIHZhciBoaWdoID0gdGhpcy5oaWdoICYgd29yZC5oaWdoO1xuXHQgICAgICAgICAgICAvLyB2YXIgbG93ID0gdGhpcy5sb3cgJiB3b3JkLmxvdztcblxuXHQgICAgICAgICAgICAvLyByZXR1cm4gWDY0V29yZC5jcmVhdGUoaGlnaCwgbG93KTtcblx0ICAgICAgICAvLyB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQml0d2lzZSBPUnMgdGhpcyB3b3JkIHdpdGggdGhlIHBhc3NlZCB3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtYNjRXb3JkfSB3b3JkIFRoZSB4NjQtV29yZCB0byBPUiB3aXRoIHRoaXMgd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1g2NFdvcmR9IEEgbmV3IHg2NC1Xb3JkIG9iamVjdCBhZnRlciBPUmluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIG9yZWQgPSB4NjRXb3JkLm9yKGFub3RoZXJYNjRXb3JkKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICAvLyBvcjogZnVuY3Rpb24gKHdvcmQpIHtcblx0ICAgICAgICAgICAgLy8gdmFyIGhpZ2ggPSB0aGlzLmhpZ2ggfCB3b3JkLmhpZ2g7XG5cdCAgICAgICAgICAgIC8vIHZhciBsb3cgPSB0aGlzLmxvdyB8IHdvcmQubG93O1xuXG5cdCAgICAgICAgICAgIC8vIHJldHVybiBYNjRXb3JkLmNyZWF0ZShoaWdoLCBsb3cpO1xuXHQgICAgICAgIC8vIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBCaXR3aXNlIFhPUnMgdGhpcyB3b3JkIHdpdGggdGhlIHBhc3NlZCB3b3JkLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtYNjRXb3JkfSB3b3JkIFRoZSB4NjQtV29yZCB0byBYT1Igd2l0aCB0aGlzIHdvcmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtYNjRXb3JkfSBBIG5ldyB4NjQtV29yZCBvYmplY3QgYWZ0ZXIgWE9SaW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgeG9yZWQgPSB4NjRXb3JkLnhvcihhbm90aGVyWDY0V29yZCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgLy8geG9yOiBmdW5jdGlvbiAod29yZCkge1xuXHQgICAgICAgICAgICAvLyB2YXIgaGlnaCA9IHRoaXMuaGlnaCBeIHdvcmQuaGlnaDtcblx0ICAgICAgICAgICAgLy8gdmFyIGxvdyA9IHRoaXMubG93IF4gd29yZC5sb3c7XG5cblx0ICAgICAgICAgICAgLy8gcmV0dXJuIFg2NFdvcmQuY3JlYXRlKGhpZ2gsIGxvdyk7XG5cdCAgICAgICAgLy8gfSxcblxuXHQgICAgICAgIC8qKlxuXHQgICAgICAgICAqIFNoaWZ0cyB0aGlzIHdvcmQgbiBiaXRzIHRvIHRoZSBsZWZ0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7WDY0V29yZH0gQSBuZXcgeDY0LVdvcmQgb2JqZWN0IGFmdGVyIHNoaWZ0aW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgc2hpZnRlZCA9IHg2NFdvcmQuc2hpZnRMKDI1KTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICAvLyBzaGlmdEw6IGZ1bmN0aW9uIChuKSB7XG5cdCAgICAgICAgICAgIC8vIGlmIChuIDwgMzIpIHtcblx0ICAgICAgICAgICAgICAgIC8vIHZhciBoaWdoID0gKHRoaXMuaGlnaCA8PCBuKSB8ICh0aGlzLmxvdyA+Pj4gKDMyIC0gbikpO1xuXHQgICAgICAgICAgICAgICAgLy8gdmFyIGxvdyA9IHRoaXMubG93IDw8IG47XG5cdCAgICAgICAgICAgIC8vIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICAvLyB2YXIgaGlnaCA9IHRoaXMubG93IDw8IChuIC0gMzIpO1xuXHQgICAgICAgICAgICAgICAgLy8gdmFyIGxvdyA9IDA7XG5cdCAgICAgICAgICAgIC8vIH1cblxuXHQgICAgICAgICAgICAvLyByZXR1cm4gWDY0V29yZC5jcmVhdGUoaGlnaCwgbG93KTtcblx0ICAgICAgICAvLyB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogU2hpZnRzIHRoaXMgd29yZCBuIGJpdHMgdG8gdGhlIHJpZ2h0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHNoaWZ0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHJldHVybiB7WDY0V29yZH0gQSBuZXcgeDY0LVdvcmQgb2JqZWN0IGFmdGVyIHNoaWZ0aW5nLlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQGV4YW1wbGVcblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqICAgICB2YXIgc2hpZnRlZCA9IHg2NFdvcmQuc2hpZnRSKDcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIC8vIHNoaWZ0UjogZnVuY3Rpb24gKG4pIHtcblx0ICAgICAgICAgICAgLy8gaWYgKG4gPCAzMikge1xuXHQgICAgICAgICAgICAgICAgLy8gdmFyIGxvdyA9ICh0aGlzLmxvdyA+Pj4gbikgfCAodGhpcy5oaWdoIDw8ICgzMiAtIG4pKTtcblx0ICAgICAgICAgICAgICAgIC8vIHZhciBoaWdoID0gdGhpcy5oaWdoID4+PiBuO1xuXHQgICAgICAgICAgICAvLyB9IGVsc2Uge1xuXHQgICAgICAgICAgICAgICAgLy8gdmFyIGxvdyA9IHRoaXMuaGlnaCA+Pj4gKG4gLSAzMik7XG5cdCAgICAgICAgICAgICAgICAvLyB2YXIgaGlnaCA9IDA7XG5cdCAgICAgICAgICAgIC8vIH1cblxuXHQgICAgICAgICAgICAvLyByZXR1cm4gWDY0V29yZC5jcmVhdGUoaGlnaCwgbG93KTtcblx0ICAgICAgICAvLyB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogUm90YXRlcyB0aGlzIHdvcmQgbiBiaXRzIHRvIHRoZSBsZWZ0LlxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IG4gVGhlIG51bWJlciBvZiBiaXRzIHRvIHJvdGF0ZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1g2NFdvcmR9IEEgbmV3IHg2NC1Xb3JkIG9iamVjdCBhZnRlciByb3RhdGluZy5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHJvdGF0ZWQgPSB4NjRXb3JkLnJvdEwoMjUpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIC8vIHJvdEw6IGZ1bmN0aW9uIChuKSB7XG5cdCAgICAgICAgICAgIC8vIHJldHVybiB0aGlzLnNoaWZ0TChuKS5vcih0aGlzLnNoaWZ0Uig2NCAtIG4pKTtcblx0ICAgICAgICAvLyB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogUm90YXRlcyB0aGlzIHdvcmQgbiBiaXRzIHRvIHRoZSByaWdodC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBwYXJhbSB7bnVtYmVyfSBuIFRoZSBudW1iZXIgb2YgYml0cyB0byByb3RhdGUuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtYNjRXb3JkfSBBIG5ldyB4NjQtV29yZCBvYmplY3QgYWZ0ZXIgcm90YXRpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciByb3RhdGVkID0geDY0V29yZC5yb3RSKDcpO1xuXHQgICAgICAgICAqL1xuXHQgICAgICAgIC8vIHJvdFI6IGZ1bmN0aW9uIChuKSB7XG5cdCAgICAgICAgICAgIC8vIHJldHVybiB0aGlzLnNoaWZ0UihuKS5vcih0aGlzLnNoaWZ0TCg2NCAtIG4pKTtcblx0ICAgICAgICAvLyB9LFxuXG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogQWRkcyB0aGlzIHdvcmQgd2l0aCB0aGUgcGFzc2VkIHdvcmQuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge1g2NFdvcmR9IHdvcmQgVGhlIHg2NC1Xb3JkIHRvIGFkZCB3aXRoIHRoaXMgd29yZC5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEByZXR1cm4ge1g2NFdvcmR9IEEgbmV3IHg2NC1Xb3JkIG9iamVjdCBhZnRlciBhZGRpbmcuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciBhZGRlZCA9IHg2NFdvcmQuYWRkKGFub3RoZXJYNjRXb3JkKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICAvLyBhZGQ6IGZ1bmN0aW9uICh3b3JkKSB7XG5cdCAgICAgICAgICAgIC8vIHZhciBsb3cgPSAodGhpcy5sb3cgKyB3b3JkLmxvdykgfCAwO1xuXHQgICAgICAgICAgICAvLyB2YXIgY2FycnkgPSAobG93ID4+PiAwKSA8ICh0aGlzLmxvdyA+Pj4gMCkgPyAxIDogMDtcblx0ICAgICAgICAgICAgLy8gdmFyIGhpZ2ggPSAodGhpcy5oaWdoICsgd29yZC5oaWdoICsgY2FycnkpIHwgMDtcblxuXHQgICAgICAgICAgICAvLyByZXR1cm4gWDY0V29yZC5jcmVhdGUoaGlnaCwgbG93KTtcblx0ICAgICAgICAvLyB9XG5cdCAgICB9KTtcblxuXHQgICAgLyoqXG5cdCAgICAgKiBBbiBhcnJheSBvZiA2NC1iaXQgd29yZHMuXG5cdCAgICAgKlxuXHQgICAgICogQHByb3BlcnR5IHtBcnJheX0gd29yZHMgVGhlIGFycmF5IG9mIENyeXB0b0pTLng2NC5Xb3JkIG9iamVjdHMuXG5cdCAgICAgKiBAcHJvcGVydHkge251bWJlcn0gc2lnQnl0ZXMgVGhlIG51bWJlciBvZiBzaWduaWZpY2FudCBieXRlcyBpbiB0aGlzIHdvcmQgYXJyYXkuXG5cdCAgICAgKi9cblx0ICAgIHZhciBYNjRXb3JkQXJyYXkgPSBDX3g2NC5Xb3JkQXJyYXkgPSBCYXNlLmV4dGVuZCh7XG5cdCAgICAgICAgLyoqXG5cdCAgICAgICAgICogSW5pdGlhbGl6ZXMgYSBuZXdseSBjcmVhdGVkIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcGFyYW0ge0FycmF5fSB3b3JkcyAoT3B0aW9uYWwpIEFuIGFycmF5IG9mIENyeXB0b0pTLng2NC5Xb3JkIG9iamVjdHMuXG5cdCAgICAgICAgICogQHBhcmFtIHtudW1iZXJ9IHNpZ0J5dGVzIChPcHRpb25hbCkgVGhlIG51bWJlciBvZiBzaWduaWZpY2FudCBieXRlcyBpbiB0aGUgd29yZHMuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy54NjQuV29yZEFycmF5LmNyZWF0ZSgpO1xuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB3b3JkQXJyYXkgPSBDcnlwdG9KUy54NjQuV29yZEFycmF5LmNyZWF0ZShbXG5cdCAgICAgICAgICogICAgICAgICBDcnlwdG9KUy54NjQuV29yZC5jcmVhdGUoMHgwMDAxMDIwMywgMHgwNDA1MDYwNyksXG5cdCAgICAgICAgICogICAgICAgICBDcnlwdG9KUy54NjQuV29yZC5jcmVhdGUoMHgxODE5MWExYiwgMHgxYzFkMWUxZilcblx0ICAgICAgICAgKiAgICAgXSk7XG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIHdvcmRBcnJheSA9IENyeXB0b0pTLng2NC5Xb3JkQXJyYXkuY3JlYXRlKFtcblx0ICAgICAgICAgKiAgICAgICAgIENyeXB0b0pTLng2NC5Xb3JkLmNyZWF0ZSgweDAwMDEwMjAzLCAweDA0MDUwNjA3KSxcblx0ICAgICAgICAgKiAgICAgICAgIENyeXB0b0pTLng2NC5Xb3JkLmNyZWF0ZSgweDE4MTkxYTFiLCAweDFjMWQxZTFmKVxuXHQgICAgICAgICAqICAgICBdLCAxMCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgaW5pdDogZnVuY3Rpb24gKHdvcmRzLCBzaWdCeXRlcykge1xuXHQgICAgICAgICAgICB3b3JkcyA9IHRoaXMud29yZHMgPSB3b3JkcyB8fCBbXTtcblxuXHQgICAgICAgICAgICBpZiAoc2lnQnl0ZXMgIT0gdW5kZWZpbmVkKSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLnNpZ0J5dGVzID0gc2lnQnl0ZXM7XG5cdCAgICAgICAgICAgIH0gZWxzZSB7XG5cdCAgICAgICAgICAgICAgICB0aGlzLnNpZ0J5dGVzID0gd29yZHMubGVuZ3RoICogODtcblx0ICAgICAgICAgICAgfVxuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDb252ZXJ0cyB0aGlzIDY0LWJpdCB3b3JkIGFycmF5IHRvIGEgMzItYml0IHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtDcnlwdG9KUy5saWIuV29yZEFycmF5fSBUaGlzIHdvcmQgYXJyYXkncyBkYXRhIGFzIGEgMzItYml0IHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAZXhhbXBsZVxuXHQgICAgICAgICAqXG5cdCAgICAgICAgICogICAgIHZhciB4MzJXb3JkQXJyYXkgPSB4NjRXb3JkQXJyYXkudG9YMzIoKTtcblx0ICAgICAgICAgKi9cblx0ICAgICAgICB0b1gzMjogZnVuY3Rpb24gKCkge1xuXHQgICAgICAgICAgICAvLyBTaG9ydGN1dHNcblx0ICAgICAgICAgICAgdmFyIHg2NFdvcmRzID0gdGhpcy53b3Jkcztcblx0ICAgICAgICAgICAgdmFyIHg2NFdvcmRzTGVuZ3RoID0geDY0V29yZHMubGVuZ3RoO1xuXG5cdCAgICAgICAgICAgIC8vIENvbnZlcnRcblx0ICAgICAgICAgICAgdmFyIHgzMldvcmRzID0gW107XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgeDY0V29yZHNMZW5ndGg7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgdmFyIHg2NFdvcmQgPSB4NjRXb3Jkc1tpXTtcblx0ICAgICAgICAgICAgICAgIHgzMldvcmRzLnB1c2goeDY0V29yZC5oaWdoKTtcblx0ICAgICAgICAgICAgICAgIHgzMldvcmRzLnB1c2goeDY0V29yZC5sb3cpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIFgzMldvcmRBcnJheS5jcmVhdGUoeDMyV29yZHMsIHRoaXMuc2lnQnl0ZXMpO1xuXHQgICAgICAgIH0sXG5cblx0ICAgICAgICAvKipcblx0ICAgICAgICAgKiBDcmVhdGVzIGEgY29weSBvZiB0aGlzIHdvcmQgYXJyYXkuXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiBAcmV0dXJuIHtYNjRXb3JkQXJyYXl9IFRoZSBjbG9uZS5cblx0ICAgICAgICAgKlxuXHQgICAgICAgICAqIEBleGFtcGxlXG5cdCAgICAgICAgICpcblx0ICAgICAgICAgKiAgICAgdmFyIGNsb25lID0geDY0V29yZEFycmF5LmNsb25lKCk7XG5cdCAgICAgICAgICovXG5cdCAgICAgICAgY2xvbmU6IGZ1bmN0aW9uICgpIHtcblx0ICAgICAgICAgICAgdmFyIGNsb25lID0gQmFzZS5jbG9uZS5jYWxsKHRoaXMpO1xuXG5cdCAgICAgICAgICAgIC8vIENsb25lIFwid29yZHNcIiBhcnJheVxuXHQgICAgICAgICAgICB2YXIgd29yZHMgPSBjbG9uZS53b3JkcyA9IHRoaXMud29yZHMuc2xpY2UoMCk7XG5cblx0ICAgICAgICAgICAgLy8gQ2xvbmUgZWFjaCBYNjRXb3JkIG9iamVjdFxuXHQgICAgICAgICAgICB2YXIgd29yZHNMZW5ndGggPSB3b3Jkcy5sZW5ndGg7XG5cdCAgICAgICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgd29yZHNMZW5ndGg7IGkrKykge1xuXHQgICAgICAgICAgICAgICAgd29yZHNbaV0gPSB3b3Jkc1tpXS5jbG9uZSgpO1xuXHQgICAgICAgICAgICB9XG5cblx0ICAgICAgICAgICAgcmV0dXJuIGNsb25lO1xuXHQgICAgICAgIH1cblx0ICAgIH0pO1xuXHR9KCkpO1xuXG5cblx0cmV0dXJuIENyeXB0b0pTO1xuXG59KSk7IiwidmFyIEN1cmwgPSByZXF1aXJlKFwiLi4vY3VybC9jdXJsXCIpO1xudmFyIEtlcmwgPSByZXF1aXJlKFwiLi4va2VybC9rZXJsXCIpO1xudmFyIENvbnZlcnRlciA9IHJlcXVpcmUoXCIuLi9jb252ZXJ0ZXIvY29udmVydGVyXCIpO1xudmFyIHRyaXRBZGQgPSByZXF1aXJlKFwiLi4vaGVscGVycy9hZGRlclwiKTtcblxuLyoqXG4qXG4qICAgQGNvbnN0cnVjdG9yIGJ1bmRsZVxuKiovXG5mdW5jdGlvbiBCdW5kbGUoKSB7XG5cbiAgICAvLyBEZWNsYXJlIGVtcHR5IGJ1bmRsZVxuICAgIHRoaXMuYnVuZGxlID0gW107XG59XG5cbi8qKlxuKlxuKlxuKiovXG5cbkJ1bmRsZS5wcm90b3R5cGUuYWRkRW50cnkgPSBmdW5jdGlvbihzaWduYXR1cmVNZXNzYWdlTGVuZ3RoLCBhZGRyZXNzLCB2YWx1ZSwgdGFnLCB0aW1lc3RhbXAsIGluZGV4KSB7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHNpZ25hdHVyZU1lc3NhZ2VMZW5ndGg7IGkrKykge1xuXG4gICAgICAgIHZhciB0cmFuc2FjdGlvbk9iamVjdCA9IG5ldyBPYmplY3QoKTtcbiAgICAgICAgdHJhbnNhY3Rpb25PYmplY3QuYWRkcmVzcyA9IGFkZHJlc3M7XG4gICAgICAgIHRyYW5zYWN0aW9uT2JqZWN0LnZhbHVlID0gaSA9PSAwID8gdmFsdWUgOiAwO1xuICAgICAgICB0cmFuc2FjdGlvbk9iamVjdC5vYnNvbGV0ZVRhZyA9IHRhZztcbiAgICAgICAgdHJhbnNhY3Rpb25PYmplY3QudGFnID0gdGFnO1xuICAgICAgICB0cmFuc2FjdGlvbk9iamVjdC50aW1lc3RhbXAgPSB0aW1lc3RhbXA7XG5cbiAgICAgICAgdGhpcy5idW5kbGVbdGhpcy5idW5kbGUubGVuZ3RoXSA9IHRyYW5zYWN0aW9uT2JqZWN0O1xuICAgIH1cbn1cblxuLyoqXG4qXG4qXG4qKi9cbkJ1bmRsZS5wcm90b3R5cGUuYWRkVHJ5dGVzID0gZnVuY3Rpb24oc2lnbmF0dXJlRnJhZ21lbnRzKSB7XG5cbiAgICB2YXIgZW1wdHlTaWduYXR1cmVGcmFnbWVudCA9ICcnO1xuICAgIHZhciBlbXB0eUhhc2ggPSAnOTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5JztcbiAgICB2YXIgZW1wdHlUYWcgPSAnOScucmVwZWF0KDI3KTtcbiAgICB2YXIgZW1wdHlUaW1lc3RhbXAgPSAnOScucmVwZWF0KDkpO1xuXG4gICAgZm9yICh2YXIgaiA9IDA7IGVtcHR5U2lnbmF0dXJlRnJhZ21lbnQubGVuZ3RoIDwgMjE4NzsgaisrKSB7XG4gICAgICAgIGVtcHR5U2lnbmF0dXJlRnJhZ21lbnQgKz0gJzknO1xuICAgIH1cblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdGhpcy5idW5kbGUubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICAvLyBGaWxsIGVtcHR5IHNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudFxuICAgICAgICB0aGlzLmJ1bmRsZVtpXS5zaWduYXR1cmVNZXNzYWdlRnJhZ21lbnQgPSBzaWduYXR1cmVGcmFnbWVudHNbaV0gPyBzaWduYXR1cmVGcmFnbWVudHNbaV0gOiBlbXB0eVNpZ25hdHVyZUZyYWdtZW50O1xuXG4gICAgICAgIC8vIEZpbGwgZW1wdHkgdHJ1bmtUcmFuc2FjdGlvblxuICAgICAgICB0aGlzLmJ1bmRsZVtpXS50cnVua1RyYW5zYWN0aW9uID0gZW1wdHlIYXNoO1xuXG4gICAgICAgIC8vIEZpbGwgZW1wdHkgYnJhbmNoVHJhbnNhY3Rpb25cbiAgICAgICAgdGhpcy5idW5kbGVbaV0uYnJhbmNoVHJhbnNhY3Rpb24gPSBlbXB0eUhhc2g7XG5cbiAgICAgICAgdGhpcy5idW5kbGVbaV0uYXR0YWNobWVudFRpbWVzdGFtcCA9IGVtcHR5VGltZXN0YW1wO1xuICAgICAgICB0aGlzLmJ1bmRsZVtpXS5hdHRhY2htZW50VGltZXN0YW1wTG93ZXJCb3VuZCA9IGVtcHR5VGltZXN0YW1wO1xuICAgICAgICB0aGlzLmJ1bmRsZVtpXS5hdHRhY2htZW50VGltZXN0YW1wVXBwZXJCb3VuZCA9IGVtcHR5VGltZXN0YW1wO1xuICAgICAgICAvLyBGaWxsIGVtcHR5IG5vbmNlXG4gICAgICAgIHRoaXMuYnVuZGxlW2ldLm5vbmNlID0gZW1wdHlUYWc7XG4gICAgfVxufVxuXG5cbi8qKlxuKlxuKlxuKiovXG5CdW5kbGUucHJvdG90eXBlLmZpbmFsaXplID0gZnVuY3Rpb24oKSB7XG4gICAgdmFyIHZhbGlkQnVuZGxlID0gZmFsc2U7XG5cbiAgd2hpbGUoIXZhbGlkQnVuZGxlKSB7XG5cbiAgICB2YXIga2VybCA9IG5ldyBLZXJsKCk7XG4gICAga2VybC5pbml0aWFsaXplKCk7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRoaXMuYnVuZGxlLmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgdmFyIHZhbHVlVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModGhpcy5idW5kbGVbaV0udmFsdWUpO1xuICAgICAgICB3aGlsZSAodmFsdWVUcml0cy5sZW5ndGggPCA4MSkge1xuICAgICAgICAgICAgdmFsdWVUcml0c1t2YWx1ZVRyaXRzLmxlbmd0aF0gPSAwO1xuICAgICAgICB9XG5cbiAgICAgICAgdmFyIHRpbWVzdGFtcFRyaXRzID0gQ29udmVydGVyLnRyaXRzKHRoaXMuYnVuZGxlW2ldLnRpbWVzdGFtcCk7XG4gICAgICAgIHdoaWxlICh0aW1lc3RhbXBUcml0cy5sZW5ndGggPCAyNykge1xuICAgICAgICAgICAgdGltZXN0YW1wVHJpdHNbdGltZXN0YW1wVHJpdHMubGVuZ3RoXSA9IDA7XG4gICAgICAgIH1cblxuICAgICAgICB2YXIgY3VycmVudEluZGV4VHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModGhpcy5idW5kbGVbaV0uY3VycmVudEluZGV4ID0gaSk7XG4gICAgICAgIHdoaWxlIChjdXJyZW50SW5kZXhUcml0cy5sZW5ndGggPCAyNykge1xuICAgICAgICAgICAgY3VycmVudEluZGV4VHJpdHNbY3VycmVudEluZGV4VHJpdHMubGVuZ3RoXSA9IDA7XG4gICAgICAgIH1cblxuICAgICAgICB2YXIgbGFzdEluZGV4VHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModGhpcy5idW5kbGVbaV0ubGFzdEluZGV4ID0gdGhpcy5idW5kbGUubGVuZ3RoIC0gMSk7XG4gICAgICAgIHdoaWxlIChsYXN0SW5kZXhUcml0cy5sZW5ndGggPCAyNykge1xuICAgICAgICAgICAgbGFzdEluZGV4VHJpdHNbbGFzdEluZGV4VHJpdHMubGVuZ3RoXSA9IDA7XG4gICAgICAgIH1cblxuICAgICAgICB2YXIgYnVuZGxlRXNzZW5jZSA9IENvbnZlcnRlci50cml0cyh0aGlzLmJ1bmRsZVtpXS5hZGRyZXNzICsgQ29udmVydGVyLnRyeXRlcyh2YWx1ZVRyaXRzKSArIHRoaXMuYnVuZGxlW2ldLm9ic29sZXRlVGFnICsgQ29udmVydGVyLnRyeXRlcyh0aW1lc3RhbXBUcml0cykgKyBDb252ZXJ0ZXIudHJ5dGVzKGN1cnJlbnRJbmRleFRyaXRzKSArIENvbnZlcnRlci50cnl0ZXMobGFzdEluZGV4VHJpdHMpKTtcbiAgICAgICAga2VybC5hYnNvcmIoYnVuZGxlRXNzZW5jZSwgMCwgYnVuZGxlRXNzZW5jZS5sZW5ndGgpO1xuICAgIH1cblxuICAgIHZhciBoYXNoID0gW107XG4gICAga2VybC5zcXVlZXplKGhhc2gsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuICAgIGhhc2ggPSBDb252ZXJ0ZXIudHJ5dGVzKGhhc2gpO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0aGlzLmJ1bmRsZS5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIHRoaXMuYnVuZGxlW2ldLmJ1bmRsZSA9IGhhc2g7XG4gICAgfVxuXG4gICAgdmFyIG5vcm1hbGl6ZWRIYXNoID0gdGhpcy5ub3JtYWxpemVkQnVuZGxlKGhhc2gpO1xuICAgIGlmKG5vcm1hbGl6ZWRIYXNoLmluZGV4T2YoMTMgLyogPSBNICovKSAhPSAtMSkge1xuICAgICAgLy8gSW5zZWN1cmUgYnVuZGxlLiBJbmNyZW1lbnQgVGFnIGFuZCByZWNvbXB1dGUgYnVuZGxlIGhhc2guXG4gICAgICB2YXIgaW5jcmVhc2VkVGFnID0gdHJpdEFkZChDb252ZXJ0ZXIudHJpdHModGhpcy5idW5kbGVbMF0ub2Jzb2xldGVUYWcpLCBbMV0pO1xuICAgICAgdGhpcy5idW5kbGVbMF0ub2Jzb2xldGVUYWcgPSBDb252ZXJ0ZXIudHJ5dGVzKGluY3JlYXNlZFRhZyk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHZhbGlkQnVuZGxlID0gdHJ1ZTtcbiAgICB9XG4gIH1cbn1cblxuLyoqXG4qICAgTm9ybWFsaXplcyB0aGUgYnVuZGxlIGhhc2hcbipcbioqL1xuQnVuZGxlLnByb3RvdHlwZS5ub3JtYWxpemVkQnVuZGxlID0gZnVuY3Rpb24oYnVuZGxlSGFzaCkge1xuXG4gICAgdmFyIG5vcm1hbGl6ZWRCdW5kbGUgPSBbXTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMzsgaSsrKSB7XG5cbiAgICAgICAgdmFyIHN1bSA9IDA7XG4gICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMjc7IGorKykge1xuXG4gICAgICAgICAgICBzdW0gKz0gKG5vcm1hbGl6ZWRCdW5kbGVbaSAqIDI3ICsgal0gPSBDb252ZXJ0ZXIudmFsdWUoQ29udmVydGVyLnRyaXRzKGJ1bmRsZUhhc2guY2hhckF0KGkgKiAyNyArIGopKSkpO1xuICAgICAgICB9XG5cbiAgICAgICAgaWYgKHN1bSA+PSAwKSB7XG5cbiAgICAgICAgICAgIHdoaWxlIChzdW0tLSA+IDApIHtcblxuICAgICAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBqIDwgMjc7IGorKykge1xuXG4gICAgICAgICAgICAgICAgICAgIGlmIChub3JtYWxpemVkQnVuZGxlW2kgKiAyNyArIGpdID4gLTEzKSB7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIG5vcm1hbGl6ZWRCdW5kbGVbaSAqIDI3ICsgal0tLTtcbiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9IGVsc2Uge1xuXG4gICAgICAgICAgICB3aGlsZSAoc3VtKysgPCAwKSB7XG5cbiAgICAgICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI3OyBqKyspIHtcblxuICAgICAgICAgICAgICAgICAgICBpZiAobm9ybWFsaXplZEJ1bmRsZVtpICogMjcgKyBqXSA8IDEzKSB7XG5cbiAgICAgICAgICAgICAgICAgICAgICAgIG5vcm1hbGl6ZWRCdW5kbGVbaSAqIDI3ICsgal0rKztcbiAgICAgICAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIG5vcm1hbGl6ZWRCdW5kbGU7XG59XG5cbm1vZHVsZS5leHBvcnRzID0gQnVuZGxlO1xuIiwiLyoqXG4gKlxuICogICBDb252ZXJzaW9uIGZ1bmN0aW9uc1xuICpcbiAqKi9cblxudmFyIFJBRElYID0gMztcbnZhciBSQURJWF9CWVRFUyA9IDI1NjtcbnZhciBNQVhfVFJJVF9WQUxVRSA9IDE7XG52YXIgTUlOX1RSSVRfVkFMVUUgPSAtMTtcbnZhciBCWVRFX0hBU0hfTEVOR1RIID0gNDg7XG5cbi8vIEFsbCBwb3NzaWJsZSB0cnl0ZSB2YWx1ZXNcbnZhciB0cnl0ZXNBbHBoYWJldCA9IFwiOUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaXCJcblxuLy8gbWFwIG9mIGFsbCB0cml0cyByZXByZXNlbnRhdGlvbnNcbnZhciB0cnl0ZXNUcml0cyA9IFtcbiAgICBbIDAsICAwLCAgMF0sXG4gICAgWyAxLCAgMCwgIDBdLFxuICAgIFstMSwgIDEsICAwXSxcbiAgICBbIDAsICAxLCAgMF0sXG4gICAgWyAxLCAgMSwgIDBdLFxuICAgIFstMSwgLTEsICAxXSxcbiAgICBbIDAsIC0xLCAgMV0sXG4gICAgWyAxLCAtMSwgIDFdLFxuICAgIFstMSwgIDAsICAxXSxcbiAgICBbIDAsICAwLCAgMV0sXG4gICAgWyAxLCAgMCwgIDFdLFxuICAgIFstMSwgIDEsICAxXSxcbiAgICBbIDAsICAxLCAgMV0sXG4gICAgWyAxLCAgMSwgIDFdLFxuICAgIFstMSwgLTEsIC0xXSxcbiAgICBbIDAsIC0xLCAtMV0sXG4gICAgWyAxLCAtMSwgLTFdLFxuICAgIFstMSwgIDAsIC0xXSxcbiAgICBbIDAsICAwLCAtMV0sXG4gICAgWyAxLCAgMCwgLTFdLFxuICAgIFstMSwgIDEsIC0xXSxcbiAgICBbIDAsICAxLCAtMV0sXG4gICAgWyAxLCAgMSwgLTFdLFxuICAgIFstMSwgLTEsICAwXSxcbiAgICBbIDAsIC0xLCAgMF0sXG4gICAgWyAxLCAtMSwgIDBdLFxuICAgIFstMSwgIDAsICAwXVxuXTtcblxuLyoqXG4gKiAgIENvbnZlcnRzIHRyeXRlcyBpbnRvIHRyaXRzXG4gKlxuICogICBAbWV0aG9kIHRyaXRzXG4gKiAgIEBwYXJhbSB7U3RyaW5nfEludH0gaW5wdXQgVHJ5dGUgdmFsdWUgdG8gYmUgY29udmVydGVkLiBDYW4gZWl0aGVyIGJlIHN0cmluZyBvciBpbnRcbiAqICAgQHBhcmFtIHtBcnJheX0gc3RhdGUgKG9wdGlvbmFsKSBzdGF0ZSB0byBiZSBtb2RpZmllZFxuICogICBAcmV0dXJucyB7QXJyYXl9IHRyaXRzXG4gKiovXG52YXIgdHJpdHMgPSBmdW5jdGlvbiggaW5wdXQsIHN0YXRlICkge1xuXG4gICAgdmFyIHRyaXRzID0gc3RhdGUgfHwgW107XG5cbiAgICBpZiAoTnVtYmVyLmlzSW50ZWdlcihpbnB1dCkpIHtcblxuICAgICAgICB2YXIgYWJzb2x1dGVWYWx1ZSA9IGlucHV0IDwgMCA/IC1pbnB1dCA6IGlucHV0O1xuXG4gICAgICAgIHdoaWxlIChhYnNvbHV0ZVZhbHVlID4gMCkge1xuXG4gICAgICAgICAgICB2YXIgcmVtYWluZGVyID0gYWJzb2x1dGVWYWx1ZSAlIDM7XG4gICAgICAgICAgICBhYnNvbHV0ZVZhbHVlID0gTWF0aC5mbG9vcihhYnNvbHV0ZVZhbHVlIC8gMyk7XG5cbiAgICAgICAgICAgIGlmIChyZW1haW5kZXIgPiAxKSB7XG4gICAgICAgICAgICAgICAgcmVtYWluZGVyID0gLTE7XG4gICAgICAgICAgICAgICAgYWJzb2x1dGVWYWx1ZSsrO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICB0cml0c1t0cml0cy5sZW5ndGhdID0gcmVtYWluZGVyO1xuICAgICAgICB9XG4gICAgICAgIGlmIChpbnB1dCA8IDApIHtcblxuICAgICAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0cml0cy5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgICAgICAgICAgdHJpdHNbaV0gPSAtdHJpdHNbaV07XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9IGVsc2Uge1xuXG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaW5wdXQubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICAgICAgdmFyIGluZGV4ID0gdHJ5dGVzQWxwaGFiZXQuaW5kZXhPZihpbnB1dC5jaGFyQXQoaSkpO1xuICAgICAgICAgICAgdHJpdHNbaSAqIDNdID0gdHJ5dGVzVHJpdHNbaW5kZXhdWzBdO1xuICAgICAgICAgICAgdHJpdHNbaSAqIDMgKyAxXSA9IHRyeXRlc1RyaXRzW2luZGV4XVsxXTtcbiAgICAgICAgICAgIHRyaXRzW2kgKiAzICsgMl0gPSB0cnl0ZXNUcml0c1tpbmRleF1bMl07XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdHJpdHM7XG59XG5cbi8qKlxuICogICBDb252ZXJ0cyB0cml0cyBpbnRvIHRyeXRlc1xuICpcbiAqICAgQG1ldGhvZCB0cnl0ZXNcbiAqICAgQHBhcmFtIHtBcnJheX0gdHJpdHNcbiAqICAgQHJldHVybnMge1N0cmluZ30gdHJ5dGVzXG4gKiovXG52YXIgdHJ5dGVzID0gZnVuY3Rpb24odHJpdHMpIHtcblxuICAgIHZhciB0cnl0ZXMgPSBcIlwiO1xuXG4gICAgZm9yICggdmFyIGkgPSAwOyBpIDwgdHJpdHMubGVuZ3RoOyBpICs9IDMgKSB7XG5cbiAgICAgICAgLy8gSXRlcmF0ZSBvdmVyIGFsbCBwb3NzaWJsZSB0cnl0ZSB2YWx1ZXMgdG8gZmluZCBjb3JyZWN0IHRyaXQgcmVwcmVzZW50YXRpb25cbiAgICAgICAgZm9yICggdmFyIGogPSAwOyBqIDwgdHJ5dGVzQWxwaGFiZXQubGVuZ3RoOyBqKysgKSB7XG5cbiAgICAgICAgICAgIGlmICggdHJ5dGVzVHJpdHNbIGogXVsgMCBdID09PSB0cml0c1sgaSBdICYmIHRyeXRlc1RyaXRzWyBqIF1bIDEgXSA9PT0gdHJpdHNbIGkgKyAxIF0gJiYgdHJ5dGVzVHJpdHNbIGogXVsgMiBdID09PSB0cml0c1sgaSArIDIgXSApIHtcblxuICAgICAgICAgICAgICAgIHRyeXRlcyArPSB0cnl0ZXNBbHBoYWJldC5jaGFyQXQoIGogKTtcbiAgICAgICAgICAgICAgICBicmVhaztcblxuICAgICAgICAgICAgfVxuXG4gICAgICAgIH1cblxuICAgIH1cblxuICAgIHJldHVybiB0cnl0ZXM7XG59XG5cbi8qKlxuICogICBDb252ZXJ0cyB0cml0cyBpbnRvIGFuIGludGVnZXIgdmFsdWVcbiAqXG4gKiAgIEBtZXRob2QgdmFsdWVcbiAqICAgQHBhcmFtIHtBcnJheX0gdHJpdHNcbiAqICAgQHJldHVybnMge2ludH0gdmFsdWVcbiAqKi9cbnZhciB2YWx1ZSA9IGZ1bmN0aW9uKHRyaXRzKSB7XG5cbiAgICB2YXIgcmV0dXJuVmFsdWUgPSAwO1xuXG4gICAgZm9yICggdmFyIGkgPSB0cml0cy5sZW5ndGg7IGktLSA+IDA7ICkge1xuXG4gICAgICAgIHJldHVyblZhbHVlID0gcmV0dXJuVmFsdWUgKiAzICsgdHJpdHNbIGkgXTtcbiAgICB9XG5cbiAgICByZXR1cm4gcmV0dXJuVmFsdWU7XG59XG5cbi8qKlxuICogICBDb252ZXJ0cyBhbiBpbnRlZ2VyIHZhbHVlIHRvIHRyaXRzXG4gKlxuICogICBAbWV0aG9kIHZhbHVlXG4gKiAgIEBwYXJhbSB7SW50fSB2YWx1ZVxuICogICBAcmV0dXJucyB7QXJyYXl9IHRyaXRzXG4gKiovXG52YXIgZnJvbVZhbHVlID0gZnVuY3Rpb24odmFsdWUpIHtcblxuICAgIHZhciBkZXN0aW5hdGlvbiA9IFtdO1xuICAgIHZhciBhYnNvbHV0ZVZhbHVlID0gdmFsdWUgPCAwID8gLXZhbHVlIDogdmFsdWU7XG4gICAgdmFyIGkgPSAwO1xuXG4gICAgd2hpbGUoIGFic29sdXRlVmFsdWUgPiAwICkge1xuXG4gICAgICAgIHZhciByZW1haW5kZXIgPSAoIGFic29sdXRlVmFsdWUgJSBSQURJWCApO1xuICAgICAgICBhYnNvbHV0ZVZhbHVlID0gTWF0aC5mbG9vciggYWJzb2x1dGVWYWx1ZSAvIFJBRElYICk7XG5cbiAgICAgICAgaWYgKCByZW1haW5kZXIgPiBNQVhfVFJJVF9WQUxVRSApIHtcblxuICAgICAgICAgICAgcmVtYWluZGVyID0gTUlOX1RSSVRfVkFMVUU7XG4gICAgICAgICAgICBhYnNvbHV0ZVZhbHVlKys7XG5cbiAgICAgICAgfVxuXG4gICAgICAgIGRlc3RpbmF0aW9uWyBpIF0gPSByZW1haW5kZXI7XG4gICAgICAgIGkrKztcblxuICAgIH1cblxuICAgIGlmICggdmFsdWUgPCAwICkge1xuXG4gICAgICAgIGZvciAoIHZhciBqID0gMDsgaiA8IGRlc3RpbmF0aW9uLmxlbmd0aDsgaisrICkge1xuXG4gICAgICAgICAgICAvLyBzd2l0Y2ggdmFsdWVzXG4gICAgICAgICAgICBkZXN0aW5hdGlvblsgaiBdID0gZGVzdGluYXRpb25bIGogXSA9PT0gMCA/IDA6IC1kZXN0aW5hdGlvblsgaiBdO1xuXG4gICAgICAgIH1cblxuICAgIH1cblxuICAgIHJldHVybiBkZXN0aW5hdGlvbjtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gICAgdHJpdHMgICAgICAgICAgIDogdHJpdHMsXG4gICAgdHJ5dGVzICAgICAgICAgIDogdHJ5dGVzLFxuICAgIHZhbHVlICAgICAgICAgICA6IHZhbHVlLFxuICAgIGZyb21WYWx1ZSAgICAgICA6IGZyb21WYWx1ZVxufTtcbiIsInZhciBJTlRfTEVOR1RIID0gMTI7XG52YXIgQllURV9MRU5HVEggPSA0ODtcbnZhciBSQURJWCA9IDM7XG4vLy8gaGV4IHJlcHJlc2VudGF0aW9uIG9mICgzXjI0MikvMlxudmFyIEhBTEZfMyA9IG5ldyBVaW50MzJBcnJheShbXG4gICAgMHhhNWNlODk2NCxcbiAgICAweDlmMDA3NjY5LFxuICAgIDB4MTQ4NDUwNGYsXG4gICAgMHgzYWRlMDBkOSxcbiAgICAweDBjMjQ0ODZlLFxuICAgIDB4NTA5NzlkNTcsXG4gICAgMHg3OWE0YzcwMixcbiAgICAweDQ4YmJhZTM2LFxuICAgIDB4YTlmNjgwOGIsXG4gICAgMHhhYTA2YTgwNSxcbiAgICAweGE4N2ZhYmRmLFxuICAgIDB4NWU2OWViZWZcbl0pO1xuXG52YXIgY2xvbmVfdWludDMyQXJyYXkgPSBmdW5jdGlvbihzb3VyY2VBcnJheSkge1xuICB2YXIgZGVzdGluYXRpb24gPSBuZXcgQXJyYXlCdWZmZXIoc291cmNlQXJyYXkuYnl0ZUxlbmd0aCk7XG4gIG5ldyBVaW50MzJBcnJheShkZXN0aW5hdGlvbikuc2V0KG5ldyBVaW50MzJBcnJheShzb3VyY2VBcnJheSkpO1xuXG4gIHJldHVybiBkZXN0aW5hdGlvbjtcbn07XG5cbnZhciB0YV9zbGljZSA9IGZ1bmN0aW9uKGFycmF5KSB7XG4gIGlmIChhcnJheS5zbGljZSAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICByZXR1cm4gYXJyYXkuc2xpY2UoKTtcbiAgfVxuXG4gIHJldHVybiBjbG9uZV91aW50MzJBcnJheShhcnJheSk7XG59O1xuXG52YXIgdGFfcmV2ZXJzZSA9IGZ1bmN0aW9uKGFycmF5KSB7XG4gIGlmIChhcnJheS5yZXZlcnNlICE9PSB1bmRlZmluZWQpIHtcbiAgICBhcnJheS5yZXZlcnNlKCk7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgdmFyIGkgPSAwLFxuICAgIG4gPSBhcnJheS5sZW5ndGgsXG4gICAgbWlkZGxlID0gTWF0aC5mbG9vcihuIC8gMiksXG4gICAgdGVtcCA9IG51bGw7XG5cbiAgZm9yICg7IGkgPCBtaWRkbGU7IGkgKz0gMSkge1xuICAgIHRlbXAgPSBhcnJheVtpXTtcbiAgICBhcnJheVtpXSA9IGFycmF5W24gLSAxIC0gaV07XG4gICAgYXJyYXlbbiAtIDEgLSBpXSA9IHRlbXA7XG4gIH1cbn07XG5cbi8vLyBuZWdhdGVzIHRoZSAodW5zaWduZWQpIGlucHV0IGFycmF5XG52YXIgYmlnaW50X25vdCA9IGZ1bmN0aW9uKGFycikge1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJyLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIGFycltpXSA9ICh+YXJyW2ldKSA+Pj4gMDtcbiAgICB9XG59O1xuXG4vLy8gcnNoaWZ0IHRoYXQgd29ya3Mgd2l0aCB1cCB0byA1M1xuLy8vIEpTJ3Mgc2hpZnQgb3BlcmF0b3JzIG9ubHkgd29yayBvbiAzMiBiaXQgaW50ZWdlcnNcbi8vLyBvdXJzIGlzIHVwIHRvIDMzIG9yIDM0IGJpdHMgdGhvdWdoLCBzb1xuLy8vIHdlIG5lZWQgdG8gaW1wbGVtZW50IHNoaWZ0aW5nIG1hbnVhbGx5XG52YXIgcnNoaWZ0ID0gZnVuY3Rpb24obnVtYmVyLCBzaGlmdCkge1xuICAgIHJldHVybiAobnVtYmVyIC8gTWF0aC5wb3coMiwgc2hpZnQpKSA+Pj4gMDtcbn07XG5cbi8vLyBzd2FwcyBlbmRpYW5uZXNzXG52YXIgc3dhcDMyID0gZnVuY3Rpb24odmFsKSB7XG4gICAgcmV0dXJuICgodmFsICYgMHhGRikgPDwgMjQpIHxcbiAgICAgICAgKCh2YWwgJiAweEZGMDApIDw8IDgpIHxcbiAgICAgICAgKCh2YWwgPj4gOCkgJiAweEZGMDApIHxcbiAgICAgICAgKCh2YWwgPj4gMjQpICYgMHhGRik7XG59XG5cbi8vLyBhZGQgd2l0aCBjYXJyeVxudmFyIGZ1bGxfYWRkID0gZnVuY3Rpb24obGgsIHJoLCBjYXJyeSkge1xuICAgIHZhciB2ID0gbGggKyByaDtcbiAgICB2YXIgbCA9IChyc2hpZnQodiwgMzIpKSAmIDB4RkZGRkZGRkY7XG4gICAgdmFyIHIgPSAodiAmIDB4RkZGRkZGRkYpID4+PiAwO1xuICAgIHZhciBjYXJyeTEgPSBsICE9IDA7XG5cbiAgICBpZiAoY2FycnkpIHtcbiAgICAgICAgdiA9IHIgKyAxO1xuICAgIH1cbiAgICBsID0gKHJzaGlmdCh2LCAzMikpICYgMHhGRkZGRkZGRjtcbiAgICByID0gKHYgJiAweEZGRkZGRkZGKSA+Pj4gMDtcbiAgICB2YXIgY2FycnkyID0gbCAhPSAwO1xuXG4gICAgcmV0dXJuIFtyLCBjYXJyeTEgfHwgY2FycnkyXTtcbn07XG5cbi8vLyBzdWJ0cmFjdHMgcmggZnJvbSBiYXNlXG52YXIgYmlnaW50X3N1YiA9IGZ1bmN0aW9uKGJhc2UsIHJoKSB7XG4gICAgdmFyIG5vYm9ycm93ID0gdHJ1ZTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYmFzZS5sZW5ndGg7IGkrKykge1xuICAgICAgICB2YXIgdmMgPSBmdWxsX2FkZChiYXNlW2ldLCAofnJoW2ldID4+PiAwKSwgbm9ib3Jyb3cpO1xuICAgICAgICBiYXNlW2ldID0gdmNbMF07XG4gICAgICAgIG5vYm9ycm93ID0gdmNbMV07XG4gICAgfVxuXG4gICAgaWYgKCFub2JvcnJvdykge1xuICAgICAgICB0aHJvdyBcIm5vYm9ycm93XCI7XG4gICAgfVxufTtcblxuLy8vIGNvbXBhcmVzIHR3byAodW5zaWduZWQpIGJpZyBpbnRlZ2Vyc1xudmFyIGJpZ2ludF9jbXAgPSBmdW5jdGlvbihsaCwgcmgpIHtcbiAgICBmb3IgKHZhciBpID0gbGgubGVuZ3RoOyBpLS0gPiAwOykge1xuICAgICAgICB2YXIgYSA9IGxoW2ldID4+PiAwO1xuICAgICAgICB2YXIgYiA9IHJoW2ldID4+PiAwO1xuICAgICAgICBpZiAoYSA8IGIpIHtcbiAgICAgICAgICAgIHJldHVybiAtMTtcbiAgICAgICAgfSBlbHNlIGlmIChhID4gYikge1xuICAgICAgICAgICAgcmV0dXJuIDE7XG4gICAgICAgIH1cbiAgICB9XG4gICAgcmV0dXJuIDA7XG59O1xuXG4vLy8gYWRkcyByaCB0byBiYXNlIGluIHBsYWNlXG52YXIgYmlnaW50X2FkZCA9IGZ1bmN0aW9uKGJhc2UsIHJoKSB7XG4gICAgdmFyIGNhcnJ5ID0gZmFsc2U7XG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBiYXNlLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgIHZhciB2YyA9IGZ1bGxfYWRkKGJhc2VbaV0sIHJoW2ldLCBjYXJyeSk7XG4gICAgICAgIGJhc2VbaV0gPSB2Y1swXTtcbiAgICAgICAgY2FycnkgPSB2Y1sxXTtcbiAgICB9XG59O1xuXG4vLy8gYWRkcyBhIHNtYWxsIChpLmUuIDwzMmJpdCkgbnVtYmVyIHRvIGJhc2VcbnZhciBiaWdpbnRfYWRkX3NtYWxsID0gZnVuY3Rpb24oYmFzZSwgb3RoZXIpIHtcbiAgICB2YXIgdmMgPSBmdWxsX2FkZChiYXNlWzBdLCBvdGhlciwgZmFsc2UpO1xuICAgIGJhc2VbMF0gPSB2Y1swXTtcbiAgICB2YXIgY2FycnkgPSB2Y1sxXTtcblxuICAgIHZhciBpID0gMTtcbiAgICB3aGlsZSAoY2FycnkgJiYgaSA8IGJhc2UubGVuZ3RoKSB7XG4gICAgICAgIHZhciB2YyA9IGZ1bGxfYWRkKGJhc2VbaV0sIDAsIGNhcnJ5KTtcbiAgICAgICAgYmFzZVtpXSA9IHZjWzBdO1xuICAgICAgICBjYXJyeSA9IHZjWzFdO1xuICAgICAgICBpICs9IDE7XG4gICAgfVxuXG4gICAgcmV0dXJuIGk7XG59O1xuXG4vLy8gY29udmVydHMgdGhlIGdpdmVuIGJ5dGUgYXJyYXkgdG8gdHJpdHNcbnZhciB3b3Jkc190b190cml0cyA9IGZ1bmN0aW9uKHdvcmRzKSB7XG4gICAgaWYgKHdvcmRzLmxlbmd0aCAhPSBJTlRfTEVOR1RIKSB7XG4gICAgICAgIHRocm93IFwiSW52YWxpZCB3b3JkcyBsZW5ndGhcIjtcbiAgICB9XG5cbiAgICB2YXIgdHJpdHMgPSBuZXcgSW50OEFycmF5KDI0Myk7XG4gICAgdmFyIGJhc2UgPSBuZXcgVWludDMyQXJyYXkod29yZHMpO1xuXG4gICAgdGFfcmV2ZXJzZShiYXNlKTtcblxuICAgIHZhciBmbGlwX3RyaXRzID0gZmFsc2U7XG4gICAgaWYgKGJhc2VbSU5UX0xFTkdUSCAtIDFdID4+IDMxID09IDApIHtcbiAgICAgICAgLy8gcG9zaXRpdmUgdHdvJ3MgY29tcGxlbWVudCBudW1iZXIuXG4gICAgICAgIC8vIGFkZCBIQUxGXzMgdG8gbW92ZSBpdCB0byB0aGUgcmlnaHQgcGxhY2UuXG4gICAgICAgIGJpZ2ludF9hZGQoYmFzZSwgSEFMRl8zKTtcbiAgICB9IGVsc2Uge1xuICAgICAgICAvLyBuZWdhdGl2ZSBudW1iZXIuXG4gICAgICAgIGJpZ2ludF9ub3QoYmFzZSk7XG4gICAgICAgIGlmIChiaWdpbnRfY21wKGJhc2UsIEhBTEZfMykgPiAwKSB7XG4gICAgICAgICAgICBiaWdpbnRfc3ViKGJhc2UsIEhBTEZfMyk7XG4gICAgICAgICAgICBmbGlwX3RyaXRzID0gdHJ1ZTtcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vLyBiaWdpbnQgaXMgYmV0d2VlbiAodW5zaWduZWQpIEhBTEZfMyBhbmQgKDIqKjM4NCAtIDMqKjI0Mi8yKS5cbiAgICAgICAgICAgIGJpZ2ludF9hZGRfc21hbGwoYmFzZSwgMSk7XG4gICAgICAgICAgICB2YXIgdG1wID0gdGFfc2xpY2UoSEFMRl8zKTtcbiAgICAgICAgICAgIGJpZ2ludF9zdWIodG1wLCBiYXNlKTtcbiAgICAgICAgICAgIGJhc2UgPSB0bXA7XG4gICAgICAgIH1cbiAgICB9XG5cblxuICAgIHZhciByZW0gPSAwO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCAyNDI7IGkrKykge1xuICAgICAgICByZW0gPSAwO1xuICAgICAgICBmb3IgKHZhciBqID0gSU5UX0xFTkdUSCAtIDE7IGogPj0gMDsgai0tKSB7XG4gICAgICAgICAgICB2YXIgbGhzID0gKHJlbSAhPSAwID8gcmVtICogMHhGRkZGRkZGRiArIHJlbSA6IDApICsgYmFzZVtqXTtcbiAgICAgICAgICAgIHZhciByaHMgPSBSQURJWDtcblxuICAgICAgICAgICAgdmFyIHEgPSAobGhzIC8gcmhzKSA+Pj4gMDtcbiAgICAgICAgICAgIHZhciByID0gKGxocyAlIHJocykgPj4+IDA7XG5cbiAgICAgICAgICAgIGJhc2Vbal0gPSBxO1xuICAgICAgICAgICAgcmVtID0gcjtcbiAgICAgICAgfVxuXG4gICAgICAgIHRyaXRzW2ldID0gcmVtIC0gMTtcbiAgICB9XG5cbiAgICBpZiAoZmxpcF90cml0cykge1xuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IHRyaXRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICB0cml0c1tpXSA9IC10cml0c1tpXTtcbiAgICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB0cml0cztcbn1cblxudmFyIGlzX251bGwgPSBmdW5jdGlvbihhcnIpIHtcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFyci5sZW5ndGg7IGkrKykge1xuICAgICAgICBpZiAoYXJyW2ldICE9IDApIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiB0cnVlO1xufVxuXG52YXIgdHJpdHNfdG9fd29yZHMgPSBmdW5jdGlvbih0cml0cykge1xuICAgIGlmICh0cml0cy5sZW5ndGggIT0gMjQzKSB7XG4gICAgICAgIHRocm93IFwiSW52YWxpZCB0cml0cyBsZW5ndGhcIjtcbiAgICB9XG5cbiAgICB2YXIgYmFzZSA9IG5ldyBVaW50MzJBcnJheShJTlRfTEVOR1RIKTtcblxuICAgIGlmICh0cml0cy5zbGljZSgwLCAyNDIpLmV2ZXJ5KGZ1bmN0aW9uKGEpIHtcbiAgICAgICAgICAgIGEgPT0gLTFcbiAgICAgICAgfSkpIHtcbiAgICAgICAgYmFzZSA9IHRhX3NsaWNlKEhBTEZfMyk7XG4gICAgICAgIGJpZ2ludF9ub3QoYmFzZSk7XG4gICAgICAgIGJpZ2ludF9hZGRfc21hbGwoYmFzZSwgMSk7XG4gICAgfSBlbHNlIHtcbiAgICAgICAgdmFyIHNpemUgPSAxO1xuICAgICAgICBmb3IgKHZhciBpID0gdHJpdHMubGVuZ3RoIC0gMTsgaS0tID4gMDspIHtcbiAgICAgICAgICAgIHZhciB0cml0ID0gdHJpdHNbaV0gKyAxO1xuXG4gICAgICAgICAgICAvL211bHRpcGx5IGJ5IHJhZGl4XG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHN6ID0gc2l6ZTtcbiAgICAgICAgICAgICAgICB2YXIgY2FycnkgPSAwO1xuXG4gICAgICAgICAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCBzejsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgIHZhciB2ID0gYmFzZVtqXSAqIFJBRElYICsgY2Fycnk7XG4gICAgICAgICAgICAgICAgICAgIGNhcnJ5ID0gcnNoaWZ0KHYsIDMyKTtcbiAgICAgICAgICAgICAgICAgICAgYmFzZVtqXSA9ICh2ICYgMHhGRkZGRkZGRikgPj4+IDA7XG4gICAgICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAgICAgaWYgKGNhcnJ5ID4gMCkge1xuICAgICAgICAgICAgICAgICAgICBiYXNlW3N6XSA9IGNhcnJ5O1xuICAgICAgICAgICAgICAgICAgICBzaXplICs9IDE7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvL2FkZGl0aW9uXG4gICAgICAgICAgICB7XG4gICAgICAgICAgICAgICAgdmFyIHN6ID0gYmlnaW50X2FkZF9zbWFsbChiYXNlLCB0cml0KTtcbiAgICAgICAgICAgICAgICBpZiAoc3ogPiBzaXplKSB7XG4gICAgICAgICAgICAgICAgICAgIHNpemUgPSBzejtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWlzX251bGwoYmFzZSkpIHtcbiAgICAgICAgICAgIGlmIChiaWdpbnRfY21wKEhBTEZfMywgYmFzZSkgPD0gMCkge1xuICAgICAgICAgICAgICAgIC8vIGJhc2UgPj0gSEFMRl8zXG4gICAgICAgICAgICAgICAgLy8ganVzdCBkbyBiYXNlIC0gSEFMRl8zXG4gICAgICAgICAgICAgICAgYmlnaW50X3N1YihiYXNlLCBIQUxGXzMpO1xuICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAvLyBiYXNlIDwgSEFMRl8zXG4gICAgICAgICAgICAgICAgLy8gc28gd2UgbmVlZCB0byB0cmFuc2Zvcm0gaXQgdG8gYSB0d28ncyBjb21wbGVtZW50IHJlcHJlc2VudGF0aW9uXG4gICAgICAgICAgICAgICAgLy8gb2YgKGJhc2UgLSBIQUxGXzMpLlxuICAgICAgICAgICAgICAgIC8vIGFzIHdlIGRvbid0IGhhdmUgYSB3cmFwcGluZyAoLSksIHdlIG5lZWQgdG8gdXNlIHNvbWUgYml0IG1hZ2ljXG4gICAgICAgICAgICAgICAgdmFyIHRtcCA9IHRhX3NsaWNlKEhBTEZfMyk7XG4gICAgICAgICAgICAgICAgYmlnaW50X3N1Yih0bXAsIGJhc2UpO1xuICAgICAgICAgICAgICAgIGJpZ2ludF9ub3QodG1wKTtcbiAgICAgICAgICAgICAgICBiaWdpbnRfYWRkX3NtYWxsKHRtcCwgMSk7XG4gICAgICAgICAgICAgICAgYmFzZSA9IHRtcDtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cblxuICAgIHRhX3JldmVyc2UoYmFzZSk7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJhc2UubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYmFzZVtpXSA9IHN3YXAzMihiYXNlW2ldKTtcbiAgICB9XG5cbiAgICByZXR1cm4gYmFzZTtcbn07XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICAgIHRyaXRzX3RvX3dvcmRzOiB0cml0c190b193b3JkcyxcbiAgICB3b3Jkc190b190cml0czogd29yZHNfdG9fdHJpdHNcbn07XG4iLCJ2YXIgQ29udmVydGVyID0gcmVxdWlyZShcIi4uL2NvbnZlcnRlci9jb252ZXJ0ZXJcIik7XG5cbi8qKlxuKiogICAgICBDcnlwdG9ncmFwaGljIHJlbGF0ZWQgZnVuY3Rpb25zIHRvIElPVEEncyBDdXJsIChzcG9uZ2UgZnVuY3Rpb24pXG4qKi9cblxudmFyIE5VTUJFUl9PRl9ST1VORFMgPSA4MTtcbnZhciBIQVNIX0xFTkdUSCA9IDI0MztcbnZhciBTVEFURV9MRU5HVEggPSAzICogSEFTSF9MRU5HVEg7XG5cbmZ1bmN0aW9uIEN1cmwocm91bmRzKSB7XG4gICAgaWYgKHJvdW5kcykge1xuICAgICAgdGhpcy5yb3VuZHMgPSByb3VuZHM7XG4gICAgfSBlbHNlIHtcbiAgICAgIHRoaXMucm91bmRzID0gTlVNQkVSX09GX1JPVU5EUztcbiAgICB9XG4gICAgLy8gdHJ1dGggdGFibGVcbiAgICB0aGlzLnRydXRoVGFibGUgPSBbMSwgMCwgLTEsIDIsIDEsIC0xLCAwLCAyLCAtMSwgMSwgMF07XG59XG5cbkN1cmwuSEFTSF9MRU5HVEggPSBIQVNIX0xFTkdUSDtcblxuLyoqXG4qICAgSW5pdGlhbGl6ZXMgdGhlIHN0YXRlIHdpdGggU1RBVEVfTEVOR1RIIHRyaXRzXG4qXG4qICAgQG1ldGhvZCBpbml0aWFsaXplXG4qKi9cbkN1cmwucHJvdG90eXBlLmluaXRpYWxpemUgPSBmdW5jdGlvbihzdGF0ZSwgbGVuZ3RoKSB7XG5cbiAgICBpZiAoc3RhdGUpIHtcblxuICAgICAgICB0aGlzLnN0YXRlID0gc3RhdGU7XG5cbiAgICB9IGVsc2Uge1xuXG4gICAgICAgIHRoaXMuc3RhdGUgPSBbXTtcblxuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IFNUQVRFX0xFTkdUSDsgaSsrKSB7XG5cbiAgICAgICAgICAgIHRoaXMuc3RhdGVbaV0gPSAwO1xuXG4gICAgICAgIH1cbiAgICB9XG59XG5cbkN1cmwucHJvdG90eXBlLnJlc2V0ID0gZnVuY3Rpb24oKSB7XG4gIHRoaXMuaW5pdGlhbGl6ZSgpO1xufVxuXG4vKipcbiogICBTcG9uZ2UgYWJzb3JiIGZ1bmN0aW9uXG4qXG4qICAgQG1ldGhvZCBhYnNvcmJcbioqL1xuQ3VybC5wcm90b3R5cGUuYWJzb3JiID0gZnVuY3Rpb24odHJpdHMsIG9mZnNldCwgbGVuZ3RoKSB7XG5cbiAgICBkbyB7XG5cbiAgICAgICAgdmFyIGkgPSAwO1xuICAgICAgICB2YXIgbGltaXQgPSAobGVuZ3RoIDwgSEFTSF9MRU5HVEggPyBsZW5ndGggOiBIQVNIX0xFTkdUSCk7XG5cbiAgICAgICAgd2hpbGUgKGkgPCBsaW1pdCkge1xuXG4gICAgICAgICAgICB0aGlzLnN0YXRlW2krK10gPSB0cml0c1tvZmZzZXQrK107XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLnRyYW5zZm9ybSgpO1xuXG4gICAgfSB3aGlsZSAoKCBsZW5ndGggLT0gSEFTSF9MRU5HVEggKSA+IDApXG5cbn1cblxuLyoqXG4qICAgU3BvbmdlIHNxdWVlemUgZnVuY3Rpb25cbipcbiogICBAbWV0aG9kIHNxdWVlemVcbioqL1xuQ3VybC5wcm90b3R5cGUuc3F1ZWV6ZSA9IGZ1bmN0aW9uKHRyaXRzLCBvZmZzZXQsIGxlbmd0aCkge1xuXG4gICAgZG8ge1xuXG4gICAgICAgIHZhciBpID0gMDtcbiAgICAgICAgdmFyIGxpbWl0ID0gKGxlbmd0aCA8IEhBU0hfTEVOR1RIID8gbGVuZ3RoIDogSEFTSF9MRU5HVEgpO1xuXG4gICAgICAgIHdoaWxlIChpIDwgbGltaXQpIHtcblxuICAgICAgICAgICAgdHJpdHNbb2Zmc2V0KytdID0gdGhpcy5zdGF0ZVtpKytdO1xuICAgICAgICB9XG5cbiAgICAgICAgdGhpcy50cmFuc2Zvcm0oKTtcblxuICAgIH0gd2hpbGUgKCggbGVuZ3RoIC09IEhBU0hfTEVOR1RIICkgPiAwKVxufVxuXG4vKipcbiogICBTcG9uZ2UgdHJhbnNmb3JtIGZ1bmN0aW9uXG4qXG4qICAgQG1ldGhvZCB0cmFuc2Zvcm1cbioqL1xuQ3VybC5wcm90b3R5cGUudHJhbnNmb3JtID0gZnVuY3Rpb24oKSB7XG5cbiAgICB2YXIgc3RhdGVDb3B5ID0gW10sIGluZGV4ID0gMDtcblxuICAgIGZvciAodmFyIHJvdW5kID0gMDsgcm91bmQgPCB0aGlzLnJvdW5kczsgcm91bmQrKykge1xuXG4gICAgICAgIHN0YXRlQ29weSA9IHRoaXMuc3RhdGUuc2xpY2UoKTtcblxuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IFNUQVRFX0xFTkdUSDsgaSsrKSB7XG5cbiAgICAgICAgICAgIHRoaXMuc3RhdGVbaV0gPSB0aGlzLnRydXRoVGFibGVbc3RhdGVDb3B5W2luZGV4XSArIChzdGF0ZUNvcHlbaW5kZXggKz0gKGluZGV4IDwgMzY1ID8gMzY0IDogLTM2NSldIDw8IDIpICsgNV07XG4gICAgICAgIH1cbiAgICB9XG59XG5cbm1vZHVsZS5leHBvcnRzID0gQ3VybFxuIiwiLyogY29weXJpZ2h0IFBhdWwgSGFuZHksIDIwMTcgKi9cblxuZnVuY3Rpb24gc3VtKCBhLCBiICkge1xuXG4gICAgdmFyIHMgPSBhICsgYjtcblxuICAgIHN3aXRjaCggcyApIHtcblxuICAgICAgICBjYXNlIDI6IHJldHVybiAtMTtcbiAgICAgICAgY2FzZSAtMjogcmV0dXJuIDE7XG4gICAgICAgIGRlZmF1bHQ6IHJldHVybiBzO1xuXG4gICAgfVxufVxuXG5mdW5jdGlvbiBjb25zKCBhLCBiICkge1xuXG4gICAgaWYoIGEgPT09IGIgKSB7XG5cbiAgICAgICAgcmV0dXJuIGE7XG5cbiAgICB9XG5cbiAgICByZXR1cm4gMDtcbn1cblxuZnVuY3Rpb24gYW55KCBhLCBiICkge1xuXG4gICAgdmFyIHMgPSBhICsgYjtcblxuICAgIGlmICggcyA+IDAgKSB7XG5cbiAgICAgICAgcmV0dXJuIDE7XG5cbiAgICB9IGVsc2UgaWYgKCBzIDwgMCApIHtcblxuICAgICAgICByZXR1cm4gLTE7XG5cbiAgICB9XG5cbiAgICByZXR1cm4gMDtcbn1cblxuZnVuY3Rpb24gZnVsbF9hZGQoIGEsIGIsIGMgKSB7XG5cbiAgICB2YXIgc19hICAgICA9ICAgc3VtKCBhLCBiICk7XG4gICAgdmFyIGNfYSAgICAgPSAgIGNvbnMoIGEsIGIgKTtcbiAgICB2YXIgY19iICAgICA9ICAgY29ucyggc19hLCBjICk7XG4gICAgdmFyIGNfb3V0ICAgPSAgIGFueSggY19hLCBjX2IgKTtcbiAgICB2YXIgc19vdXQgICA9ICAgc3VtKCBzX2EsIGMgKTtcblxuICAgIHJldHVybiBbIHNfb3V0LCBjX291dCBdO1xuXG59XG5cbmZ1bmN0aW9uIGFkZCggYSwgYiApIHtcblxuICAgIHZhciBvdXQgPSBuZXcgQXJyYXkoIE1hdGgubWF4KCBhLmxlbmd0aCwgYi5sZW5ndGggKSApO1xuICAgIHZhciBjYXJyeSA9IDA7XG4gICAgdmFyIGFfaSwgYl9pO1xuXG4gICAgZm9yKCB2YXIgaSA9IDA7IGkgPCBvdXQubGVuZ3RoOyBpKysgKSB7XG5cbiAgICAgICAgYV9pID0gaSA8IGEubGVuZ3RoID8gYVsgaSBdIDogMDtcbiAgICAgICAgYl9pID0gaSA8IGIubGVuZ3RoID8gYlsgaSBdIDogMDtcbiAgICAgICAgdmFyIGZfYSA9IGZ1bGxfYWRkKCBhX2ksIGJfaSwgY2FycnkgKTtcbiAgICAgICAgb3V0WyBpIF0gPSBmX2FbIDAgXTtcbiAgICAgICAgY2FycnkgPSBmX2FbIDEgXTtcblxuICAgIH1cblxuICAgIHJldHVybiBvdXQ7XG5cbn1cblxubW9kdWxlLmV4cG9ydHMgPSBhZGQ7XG4iLCJ2YXIgQ3VybCA9IHJlcXVpcmUoXCIuLi9jdXJsL2N1cmxcIik7XG52YXIgQ29udmVydGVyID0gcmVxdWlyZShcIi4uL2NvbnZlcnRlci9jb252ZXJ0ZXJcIik7XG52YXIgSE1BQ19ST1VORFMgPSAyNztcblxuZnVuY3Rpb24gaG1hYyhrZXkpIHtcbiAgICB0aGlzLl9rZXkgPSBDb252ZXJ0ZXIudHJpdHMoa2V5KTtcbn1cblxuaG1hYy5wcm90b3R5cGUuYWRkSE1BQyA9IGZ1bmN0aW9uKGJ1bmRsZSkge1xuICAgIHZhciBjdXJsID0gbmV3IEN1cmwoSE1BQ19ST1VORFMpO1xuICAgIHZhciBrZXkgPSB0aGlzLl9rZXk7XG4gICAgZm9yKHZhciBpID0gMDsgaSA8IGJ1bmRsZS5idW5kbGUubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgaWYgKGJ1bmRsZS5idW5kbGVbaV0udmFsdWUgPiAwKSB7XG4gICAgICAgICAgICB2YXIgYnVuZGxlSGFzaFRyaXRzID0gQ29udmVydGVyLnRyaXRzKGJ1bmRsZS5idW5kbGVbaV0uYnVuZGxlKTtcbiAgICAgICAgICAgIHZhciBobWFjID0gbmV3IEludDhBcnJheSgyNDMpO1xuICAgICAgICAgICAgY3VybC5pbml0aWFsaXplKCk7XG4gICAgICAgICAgICBjdXJsLmFic29yYihrZXkpO1xuICAgICAgICAgICAgY3VybC5hYnNvcmIoYnVuZGxlSGFzaFRyaXRzKTtcbiAgICAgICAgICAgIGN1cmwuc3F1ZWV6ZShobWFjKTtcbiAgICAgICAgICAgIHZhciBobWFjVHJ5dGVzID0gQ29udmVydGVyLnRyeXRlcyhobWFjKTtcbiAgICAgICAgICAgIGJ1bmRsZS5idW5kbGVbaV0uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50ID0gaG1hY1RyeXRlcyArIGJ1bmRsZS5idW5kbGVbaV0uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50LnN1YnN0cmluZyg4MSwgMjE4Nyk7XG4gICAgICAgIH1cbiAgICB9XG59XG5cbm1vZHVsZS5leHBvcnRzID0gaG1hYztcbiIsInZhciBDcnlwdG9KUyA9IHJlcXVpcmUoXCJjcnlwdG8tanNcIik7XG52YXIgQ29udmVydGVyID0gcmVxdWlyZShcIi4uL2NvbnZlcnRlci9jb252ZXJ0ZXJcIik7XG52YXIgQ3VybCA9IHJlcXVpcmUoXCIuLi9jdXJsL2N1cmxcIik7XG52YXIgV0NvbnZlcnRlciA9IHJlcXVpcmUoXCIuLi9jb252ZXJ0ZXIvd29yZHNcIik7XG5cbnZhciBCSVRfSEFTSF9MRU5HVEggPSAzODQ7XG5cbmZ1bmN0aW9uIEtlcmwoKSB7XG5cblxuICAgIHRoaXMuayA9IENyeXB0b0pTLmFsZ28uU0hBMy5jcmVhdGUoKTtcbiAgICB0aGlzLmsuaW5pdCh7XG4gICAgICAgIG91dHB1dExlbmd0aDogQklUX0hBU0hfTEVOR1RIXG4gICAgfSk7XG59XG5cbktlcmwuQklUX0hBU0hfTEVOR1RIID0gQklUX0hBU0hfTEVOR1RIO1xuS2VybC5IQVNIX0xFTkdUSCA9IEN1cmwuSEFTSF9MRU5HVEg7XG5cbktlcmwucHJvdG90eXBlLmluaXRpYWxpemUgPSBmdW5jdGlvbihzdGF0ZSkge31cblxuS2VybC5wcm90b3R5cGUucmVzZXQgPSBmdW5jdGlvbigpIHtcblxuICAgIHRoaXMuay5yZXNldCgpO1xuXG59XG5cbktlcmwucHJvdG90eXBlLmFic29yYiA9IGZ1bmN0aW9uKHRyaXRzLCBvZmZzZXQsIGxlbmd0aCkge1xuXG5cbiAgICBpZiAobGVuZ3RoICYmICgobGVuZ3RoICUgMjQzKSAhPT0gMCkpIHtcblxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoJ0lsbGVnYWwgbGVuZ3RoIHByb3ZpZGVkJyk7XG5cbiAgICB9XG5cbiAgICBkbyB7XG4gICAgICAgIHZhciBsaW1pdCA9IChsZW5ndGggPCBDdXJsLkhBU0hfTEVOR1RIID8gbGVuZ3RoIDogQ3VybC5IQVNIX0xFTkdUSCk7XG5cbiAgICAgICAgdmFyIHRyaXRfc3RhdGUgPSB0cml0cy5zbGljZShvZmZzZXQsIG9mZnNldCArIGxpbWl0KTtcbiAgICAgICAgb2Zmc2V0ICs9IGxpbWl0O1xuXG4gICAgICAgIC8vIGNvbnZlcnQgdHJpdCBzdGF0ZSB0byB3b3Jkc1xuICAgICAgICB2YXIgd29yZHNUb0Fic29yYiA9IFdDb252ZXJ0ZXIudHJpdHNfdG9fd29yZHModHJpdF9zdGF0ZSk7XG5cbiAgICAgICAgLy8gYWJzb3JiIHRoZSB0cml0IHN0YXQgYXMgd29yZGFycmF5XG4gICAgICAgIHRoaXMuay51cGRhdGUoXG4gICAgICAgICAgICBDcnlwdG9KUy5saWIuV29yZEFycmF5LmNyZWF0ZSh3b3Jkc1RvQWJzb3JiKSk7XG5cbiAgICB9IHdoaWxlICgobGVuZ3RoIC09IEN1cmwuSEFTSF9MRU5HVEgpID4gMCk7XG5cbn1cblxuXG5cbktlcmwucHJvdG90eXBlLnNxdWVlemUgPSBmdW5jdGlvbih0cml0cywgb2Zmc2V0LCBsZW5ndGgpIHtcblxuICAgIGlmIChsZW5ndGggJiYgKChsZW5ndGggJSAyNDMpICE9PSAwKSkge1xuXG4gICAgICAgIHRocm93IG5ldyBFcnJvcignSWxsZWdhbCBsZW5ndGggcHJvdmlkZWQnKTtcblxuICAgIH1cbiAgICBkbyB7XG5cbiAgICAgICAgLy8gZ2V0IHRoZSBoYXNoIGRpZ2VzdFxuICAgICAgICB2YXIga0NvcHkgPSB0aGlzLmsuY2xvbmUoKTtcbiAgICAgICAgdmFyIGZpbmFsID0ga0NvcHkuZmluYWxpemUoKTtcblxuICAgICAgICAvLyBDb252ZXJ0IHdvcmRzIHRvIHRyaXRzIGFuZCB0aGVuIG1hcCBpdCBpbnRvIHRoZSBpbnRlcm5hbCBzdGF0ZVxuICAgICAgICB2YXIgdHJpdF9zdGF0ZSA9IFdDb252ZXJ0ZXIud29yZHNfdG9fdHJpdHMoZmluYWwud29yZHMpO1xuXG4gICAgICAgIHZhciBpID0gMDtcbiAgICAgICAgdmFyIGxpbWl0ID0gKGxlbmd0aCA8IEN1cmwuSEFTSF9MRU5HVEggPyBsZW5ndGggOiBDdXJsLkhBU0hfTEVOR1RIKTtcblxuICAgICAgICB3aGlsZSAoaSA8IGxpbWl0KSB7XG4gICAgICAgICAgICB0cml0c1tvZmZzZXQrK10gPSB0cml0X3N0YXRlW2krK107XG4gICAgICAgIH1cblxuICAgICAgICB0aGlzLnJlc2V0KCk7XG5cbiAgICAgICAgZm9yIChpID0gMDsgaSA8IGZpbmFsLndvcmRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgICBmaW5hbC53b3Jkc1tpXSA9IGZpbmFsLndvcmRzW2ldIF4gMHhGRkZGRkZGRjtcbiAgICAgICAgfVxuXG4gICAgICAgIHRoaXMuay51cGRhdGUoZmluYWwpO1xuXG4gICAgfSB3aGlsZSAoKGxlbmd0aCAtPSBDdXJsLkhBU0hfTEVOR1RIKSA+IDApO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IEtlcmw7XG4iLCJ2YXIgQ3VybCA9IHJlcXVpcmUoXCIuLi9jdXJsL2N1cmxcIik7XG52YXIgQ29udmVydGVyID0gcmVxdWlyZShcIi4uL2NvbnZlcnRlci9jb252ZXJ0ZXJcIik7XG52YXIgQnVuZGxlID0gcmVxdWlyZShcIi4uL2J1bmRsZS9idW5kbGVcIik7XG52YXIgYWRkID0gcmVxdWlyZShcIi4uL2hlbHBlcnMvYWRkZXJcIik7XG5cbi8qKlxuKiAgICAgICAgICAgU2lnbmluZyByZWxhdGVkIGZ1bmN0aW9uc1xuKlxuKiovXG52YXIga2V5ID0gZnVuY3Rpb24oc2VlZCwgaW5kZXgsIGxlbmd0aCkge1xuXG4gICAgd2hpbGUgKChzZWVkLmxlbmd0aCAlIDI0MykgIT09IDApIHtcbiAgICAgIHNlZWQucHVzaCgwKTtcbiAgICB9XG5cbiAgICB2YXIgaW5kZXhUcml0cyA9IENvbnZlcnRlci5mcm9tVmFsdWUoIGluZGV4ICk7XG4gICAgdmFyIHN1YnNlZWQgPSBhZGQoIHNlZWQuc2xpY2UoICksIGluZGV4VHJpdHMgKTtcblxuICAgIHZhciBjdXJsID0gbmV3IEN1cmwoICk7XG5cbiAgICBjdXJsLmluaXRpYWxpemUoICk7XG4gICAgY3VybC5hYnNvcmIoc3Vic2VlZCwgMCwgc3Vic2VlZC5sZW5ndGgpO1xuICAgIGN1cmwuc3F1ZWV6ZShzdWJzZWVkLCAwLCBzdWJzZWVkLmxlbmd0aCk7XG5cbiAgICBjdXJsLmluaXRpYWxpemUoICk7XG4gICAgY3VybC5hYnNvcmIoc3Vic2VlZCwgMCwgc3Vic2VlZC5sZW5ndGgpO1xuXG4gICAgdmFyIGtleSA9IFtdLCBvZmZzZXQgPSAwLCBidWZmZXIgPSBbXTtcblxuICAgIHdoaWxlIChsZW5ndGgtLSA+IDApIHtcblxuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI3OyBpKyspIHtcblxuICAgICAgICAgICAgY3VybC5zcXVlZXplKGJ1ZmZlciwgMCwgc3Vic2VlZC5sZW5ndGgpO1xuICAgICAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCAyNDM7IGorKykge1xuXG4gICAgICAgICAgICAgICAga2V5W29mZnNldCsrXSA9IGJ1ZmZlcltqXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4ga2V5O1xufVxuXG4vKipcbipcbipcbioqL1xudmFyIGRpZ2VzdHMgPSBmdW5jdGlvbihrZXkpIHtcblxuICAgIHZhciBkaWdlc3RzID0gW10sIGJ1ZmZlciA9IFtdO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBNYXRoLmZsb29yKGtleS5sZW5ndGggLyA2NTYxKTsgaSsrKSB7XG5cbiAgICAgICAgdmFyIGtleUZyYWdtZW50ID0ga2V5LnNsaWNlKGkgKiA2NTYxLCAoaSArIDEpICogNjU2MSk7XG5cbiAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCAyNzsgaisrKSB7XG5cbiAgICAgICAgICAgIGJ1ZmZlciA9IGtleUZyYWdtZW50LnNsaWNlKGogKiAyNDMsIChqICsgMSkgKiAyNDMpO1xuXG4gICAgICAgICAgICBmb3IgKHZhciBrID0gMDsgayA8IDI2OyBrKyspIHtcblxuICAgICAgICAgICAgICAgIHZhciBrQ3VybCA9IG5ldyBDdXJsKCk7XG4gICAgICAgICAgICAgICAga0N1cmwuaW5pdGlhbGl6ZSgpO1xuICAgICAgICAgICAgICAgIGtDdXJsLmFic29yYihidWZmZXIsIDAsIGJ1ZmZlci5sZW5ndGgpO1xuICAgICAgICAgICAgICAgIGtDdXJsLnNxdWVlemUoYnVmZmVyLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZm9yICh2YXIgayA9IDA7IGsgPCAyNDM7IGsrKykge1xuXG4gICAgICAgICAgICAgICAga2V5RnJhZ21lbnRbaiAqIDI0MyArIGtdID0gYnVmZmVyW2tdO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgdmFyIGN1cmwgPSBuZXcgQ3VybCgpXG5cbiAgICAgICAgY3VybC5pbml0aWFsaXplKCk7XG4gICAgICAgIGN1cmwuYWJzb3JiKGtleUZyYWdtZW50LCAwLCBrZXlGcmFnbWVudC5sZW5ndGgpO1xuICAgICAgICBjdXJsLnNxdWVlemUoYnVmZmVyLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI0MzsgaisrKSB7XG5cbiAgICAgICAgICAgIGRpZ2VzdHNbaSAqIDI0MyArIGpdID0gYnVmZmVyW2pdO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBkaWdlc3RzO1xufVxuXG4vKipcbipcbipcbioqL1xudmFyIGFkZHJlc3MgPSBmdW5jdGlvbihkaWdlc3RzKSB7XG5cbiAgICB2YXIgYWRkcmVzc1RyaXRzID0gW107XG5cbiAgICB2YXIgY3VybCA9IG5ldyBDdXJsKCk7XG5cbiAgICBjdXJsLmluaXRpYWxpemUoKTtcbiAgICBjdXJsLmFic29yYihkaWdlc3RzLCAwLCBkaWdlc3RzLmxlbmd0aCk7XG4gICAgY3VybC5zcXVlZXplKGFkZHJlc3NUcml0cywgMCwgQ3VybC5IQVNIX0xFTkdUSCk7XG5cbiAgICByZXR1cm4gYWRkcmVzc1RyaXRzO1xufVxuXG4vKipcbipcbipcbioqL1xudmFyIGRpZ2VzdCA9IGZ1bmN0aW9uKG5vcm1hbGl6ZWRCdW5kbGVGcmFnbWVudCwgc2lnbmF0dXJlRnJhZ21lbnQpIHtcblxuICAgIHZhciBidWZmZXIgPSBbXVxuXG4gICAgdmFyIGN1cmwgPSBuZXcgQ3VybCgpO1xuXG4gICAgY3VybC5pbml0aWFsaXplKCk7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaTwgMjc7IGkrKykge1xuICAgICAgICBidWZmZXIgPSBzaWduYXR1cmVGcmFnbWVudC5zbGljZShpICogMjQzLCAoaSArIDEpICogMjQzKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50W2ldICsgMTM7IGotLSA+IDA7ICkge1xuXG4gICAgICAgICAgICB2YXIgakN1cmwgPSBuZXcgQ3VybCgpO1xuXG4gICAgICAgICAgICBqQ3VybC5pbml0aWFsaXplKCk7XG4gICAgICAgICAgICBqQ3VybC5hYnNvcmIoYnVmZmVyLCAwLCBidWZmZXIubGVuZ3RoKTtcbiAgICAgICAgICAgIGpDdXJsLnNxdWVlemUoYnVmZmVyLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGN1cmwuYWJzb3JiKGJ1ZmZlciwgMCwgYnVmZmVyLmxlbmd0aCk7XG4gICAgfVxuXG4gICAgY3VybC5zcXVlZXplKGJ1ZmZlciwgMCwgQ3VybC5IQVNIX0xFTkdUSCk7XG4gICAgcmV0dXJuIGJ1ZmZlcjtcbn1cblxuLyoqXG4qXG4qXG4qKi9cbnZhciBzaWduYXR1cmVGcmFnbWVudCA9IGZ1bmN0aW9uKG5vcm1hbGl6ZWRCdW5kbGVGcmFnbWVudCwga2V5RnJhZ21lbnQpIHtcblxuICAgIHZhciBzaWduYXR1cmVGcmFnbWVudCA9IGtleUZyYWdtZW50LnNsaWNlKCksIGhhc2ggPSBbXTtcblxuICAgIHZhciBjdXJsID0gbmV3IEN1cmwoKTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMjc7IGkrKykge1xuXG4gICAgICAgIGhhc2ggPSBzaWduYXR1cmVGcmFnbWVudC5zbGljZShpICogMjQzLCAoaSArIDEpICogMjQzKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDEzIC0gbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50W2ldOyBqKyspIHtcblxuICAgICAgICAgICAgY3VybC5pbml0aWFsaXplKCk7XG4gICAgICAgICAgICBjdXJsLmFic29yYihoYXNoLCAwLCBoYXNoLmxlbmd0aCk7XG4gICAgICAgICAgICBjdXJsLnNxdWVlemUoaGFzaCwgMCwgQ3VybC5IQVNIX0xFTkdUSCk7XG4gICAgICAgIH1cblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI0MzsgaisrKSB7XG5cbiAgICAgICAgICAgIHNpZ25hdHVyZUZyYWdtZW50W2kgKiAyNDMgKyBqXSA9IGhhc2hbal07XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gc2lnbmF0dXJlRnJhZ21lbnQ7XG59XG5cbi8qKlxuKlxuKlxuKiovXG52YXIgdmFsaWRhdGVTaWduYXR1cmVzID0gZnVuY3Rpb24oZXhwZWN0ZWRBZGRyZXNzLCBzaWduYXR1cmVGcmFnbWVudHMsIGJ1bmRsZUhhc2gpIHtcblxuICAgIHZhciBzZWxmID0gdGhpcztcbiAgICB2YXIgYnVuZGxlID0gbmV3IEJ1bmRsZSgpO1xuXG4gICAgdmFyIG5vcm1hbGl6ZWRCdW5kbGVGcmFnbWVudHMgPSBbXTtcbiAgICB2YXIgbm9ybWFsaXplZEJ1bmRsZUhhc2ggPSBidW5kbGUubm9ybWFsaXplZEJ1bmRsZShidW5kbGVIYXNoKTtcblxuICAgIC8vIFNwbGl0IGhhc2ggaW50byAzIGZyYWdtZW50c1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMzsgaSsrKSB7XG4gICAgICAgIG5vcm1hbGl6ZWRCdW5kbGVGcmFnbWVudHNbaV0gPSBub3JtYWxpemVkQnVuZGxlSGFzaC5zbGljZShpICogMjcsIChpICsgMSkgKiAyNyk7XG4gICAgfVxuXG4gICAgLy8gR2V0IGRpZ2VzdHNcbiAgICB2YXIgZGlnZXN0cyA9IFtdO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzaWduYXR1cmVGcmFnbWVudHMubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICB2YXIgZGlnZXN0QnVmZmVyID0gZGlnZXN0KG5vcm1hbGl6ZWRCdW5kbGVGcmFnbWVudHNbaSAlIDNdLCBDb252ZXJ0ZXIudHJpdHMoc2lnbmF0dXJlRnJhZ21lbnRzW2ldKSk7XG5cbiAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCAyNDM7IGorKykge1xuXG4gICAgICAgICAgICBkaWdlc3RzW2kgKiAyNDMgKyBqXSA9IGRpZ2VzdEJ1ZmZlcltqXVxuICAgICAgICB9XG4gICAgfVxuXG4gICAgdmFyIGFkZHJlc3MgPSBDb252ZXJ0ZXIudHJ5dGVzKHNlbGYuYWRkcmVzcyhkaWdlc3RzKSk7XG5cbiAgICByZXR1cm4gKGV4cGVjdGVkQWRkcmVzcyA9PT0gYWRkcmVzcyk7XG59XG5cblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gICAga2V5ICAgICAgICAgICAgICAgICA6IGtleSxcbiAgICBkaWdlc3RzICAgICAgICAgICAgIDogZGlnZXN0cyxcbiAgICBhZGRyZXNzICAgICAgICAgICAgIDogYWRkcmVzcyxcbiAgICBkaWdlc3QgICAgICAgICAgICAgIDogZGlnZXN0LFxuICAgIHNpZ25hdHVyZUZyYWdtZW50ICAgOiBzaWduYXR1cmVGcmFnbWVudCxcbiAgICB2YWxpZGF0ZVNpZ25hdHVyZXMgIDogdmFsaWRhdGVTaWduYXR1cmVzXG59XG4iLCJ2YXIgQ3VybCA9IHJlcXVpcmUoXCIuLi9jdXJsL2N1cmxcIik7XG52YXIgS2VybCA9IHJlcXVpcmUoXCIuLi9rZXJsL2tlcmxcIik7XG52YXIgQ29udmVydGVyID0gcmVxdWlyZShcIi4uL2NvbnZlcnRlci9jb252ZXJ0ZXJcIik7XG52YXIgQnVuZGxlID0gcmVxdWlyZShcIi4uL2J1bmRsZS9idW5kbGVcIik7XG52YXIgYWRkID0gcmVxdWlyZShcIi4uL2hlbHBlcnMvYWRkZXJcIik7XG52YXIgb2xkU2lnbmluZyA9IHJlcXVpcmUoXCIuL29sZFNpZ25pbmdcIik7XG52YXIgZXJyb3JzID0gcmVxdWlyZShcIi4uLy4uL2Vycm9ycy9pbnB1dEVycm9yc1wiKTtcblxuLyoqXG4qICAgICAgICAgICBTaWduaW5nIHJlbGF0ZWQgZnVuY3Rpb25zXG4qXG4qKi9cbnZhciBrZXkgPSBmdW5jdGlvbihzZWVkLCBpbmRleCwgbGVuZ3RoKSB7XG5cbiAgICB3aGlsZSAoKHNlZWQubGVuZ3RoICUgMjQzKSAhPT0gMCkge1xuICAgICAgc2VlZC5wdXNoKDApO1xuICAgIH1cblxuICAgIHZhciBpbmRleFRyaXRzID0gQ29udmVydGVyLmZyb21WYWx1ZSggaW5kZXggKTtcbiAgICB2YXIgc3Vic2VlZCA9IGFkZCggc2VlZC5zbGljZSggKSwgaW5kZXhUcml0cyApO1xuXG4gICAgdmFyIGtlcmwgPSBuZXcgS2VybCggKTtcblxuICAgIGtlcmwuaW5pdGlhbGl6ZSggKTtcbiAgICBrZXJsLmFic29yYihzdWJzZWVkLCAwLCBzdWJzZWVkLmxlbmd0aCk7XG4gICAga2VybC5zcXVlZXplKHN1YnNlZWQsIDAsIHN1YnNlZWQubGVuZ3RoKTtcblxuICAgIGtlcmwucmVzZXQoICk7XG4gICAga2VybC5hYnNvcmIoc3Vic2VlZCwgMCwgc3Vic2VlZC5sZW5ndGgpO1xuXG4gICAgdmFyIGtleSA9IFtdLCBvZmZzZXQgPSAwLCBidWZmZXIgPSBbXTtcblxuICAgIHdoaWxlIChsZW5ndGgtLSA+IDApIHtcblxuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IDI3OyBpKyspIHtcblxuICAgICAgICAgICAga2VybC5zcXVlZXplKGJ1ZmZlciwgMCwgc3Vic2VlZC5sZW5ndGgpO1xuICAgICAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCAyNDM7IGorKykge1xuXG4gICAgICAgICAgICAgICAga2V5W29mZnNldCsrXSA9IGJ1ZmZlcltqXTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cbiAgICByZXR1cm4ga2V5O1xufVxuXG4vKipcbipcbipcbioqL1xudmFyIGRpZ2VzdHMgPSBmdW5jdGlvbihrZXkpIHtcblxuICAgIHZhciBkaWdlc3RzID0gW10sIGJ1ZmZlciA9IFtdO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBNYXRoLmZsb29yKGtleS5sZW5ndGggLyA2NTYxKTsgaSsrKSB7XG5cbiAgICAgICAgdmFyIGtleUZyYWdtZW50ID0ga2V5LnNsaWNlKGkgKiA2NTYxLCAoaSArIDEpICogNjU2MSk7XG5cbiAgICAgICAgZm9yICh2YXIgaiA9IDA7IGogPCAyNzsgaisrKSB7XG5cbiAgICAgICAgICAgIGJ1ZmZlciA9IGtleUZyYWdtZW50LnNsaWNlKGogKiAyNDMsIChqICsgMSkgKiAyNDMpO1xuXG4gICAgICAgICAgICBmb3IgKHZhciBrID0gMDsgayA8IDI2OyBrKyspIHtcblxuICAgICAgICAgICAgICAgIHZhciBrS2VybCA9IG5ldyBLZXJsKCk7XG4gICAgICAgICAgICAgICAga0tlcmwuaW5pdGlhbGl6ZSgpO1xuICAgICAgICAgICAgICAgIGtLZXJsLmFic29yYihidWZmZXIsIDAsIGJ1ZmZlci5sZW5ndGgpO1xuICAgICAgICAgICAgICAgIGtLZXJsLnNxdWVlemUoYnVmZmVyLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZm9yICh2YXIgayA9IDA7IGsgPCAyNDM7IGsrKykge1xuXG4gICAgICAgICAgICAgICAga2V5RnJhZ21lbnRbaiAqIDI0MyArIGtdID0gYnVmZmVyW2tdO1xuICAgICAgICAgICAgfVxuICAgICAgICB9XG5cbiAgICAgICAgdmFyIGtlcmwgPSBuZXcgS2VybCgpXG5cbiAgICAgICAga2VybC5pbml0aWFsaXplKCk7XG4gICAgICAgIGtlcmwuYWJzb3JiKGtleUZyYWdtZW50LCAwLCBrZXlGcmFnbWVudC5sZW5ndGgpO1xuICAgICAgICBrZXJsLnNxdWVlemUoYnVmZmVyLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI0MzsgaisrKSB7XG5cbiAgICAgICAgICAgIGRpZ2VzdHNbaSAqIDI0MyArIGpdID0gYnVmZmVyW2pdO1xuICAgICAgICB9XG4gICAgfVxuICAgIHJldHVybiBkaWdlc3RzO1xufVxuXG4vKipcbipcbipcbioqL1xudmFyIGFkZHJlc3MgPSBmdW5jdGlvbihkaWdlc3RzKSB7XG5cbiAgICB2YXIgYWRkcmVzc1RyaXRzID0gW107XG5cbiAgICB2YXIga2VybCA9IG5ldyBLZXJsKCk7XG5cbiAgICBrZXJsLmluaXRpYWxpemUoKTtcbiAgICBrZXJsLmFic29yYihkaWdlc3RzLCAwLCBkaWdlc3RzLmxlbmd0aCk7XG4gICAga2VybC5zcXVlZXplKGFkZHJlc3NUcml0cywgMCwgQ3VybC5IQVNIX0xFTkdUSCk7XG5cbiAgICByZXR1cm4gYWRkcmVzc1RyaXRzO1xufVxuXG4vKipcbipcbipcbioqL1xudmFyIGRpZ2VzdCA9IGZ1bmN0aW9uKG5vcm1hbGl6ZWRCdW5kbGVGcmFnbWVudCwgc2lnbmF0dXJlRnJhZ21lbnQpIHtcblxuICAgIHZhciBidWZmZXIgPSBbXVxuXG4gICAgdmFyIGtlcmwgPSBuZXcgS2VybCgpO1xuXG4gICAga2VybC5pbml0aWFsaXplKCk7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaTwgMjc7IGkrKykge1xuICAgICAgICBidWZmZXIgPSBzaWduYXR1cmVGcmFnbWVudC5zbGljZShpICogMjQzLCAoaSArIDEpICogMjQzKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50W2ldICsgMTM7IGotLSA+IDA7ICkge1xuXG4gICAgICAgICAgICB2YXIgaktlcmwgPSBuZXcgS2VybCgpO1xuXG4gICAgICAgICAgICBqS2VybC5pbml0aWFsaXplKCk7XG4gICAgICAgICAgICBqS2VybC5hYnNvcmIoYnVmZmVyLCAwLCBidWZmZXIubGVuZ3RoKTtcbiAgICAgICAgICAgIGpLZXJsLnNxdWVlemUoYnVmZmVyLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcbiAgICAgICAgfVxuXG4gICAgICAgIGtlcmwuYWJzb3JiKGJ1ZmZlciwgMCwgYnVmZmVyLmxlbmd0aCk7XG4gICAgfVxuXG4gICAga2VybC5zcXVlZXplKGJ1ZmZlciwgMCwgQ3VybC5IQVNIX0xFTkdUSCk7XG4gICAgcmV0dXJuIGJ1ZmZlcjtcbn1cblxuLyoqXG4qXG4qXG4qKi9cbnZhciBzaWduYXR1cmVGcmFnbWVudCA9IGZ1bmN0aW9uKG5vcm1hbGl6ZWRCdW5kbGVGcmFnbWVudCwga2V5RnJhZ21lbnQpIHtcblxuICAgIHZhciBzaWduYXR1cmVGcmFnbWVudCA9IGtleUZyYWdtZW50LnNsaWNlKCksIGhhc2ggPSBbXTtcblxuICAgIHZhciBrZXJsID0gbmV3IEtlcmwoKTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgMjc7IGkrKykge1xuXG4gICAgICAgIGhhc2ggPSBzaWduYXR1cmVGcmFnbWVudC5zbGljZShpICogMjQzLCAoaSArIDEpICogMjQzKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDEzIC0gbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50W2ldOyBqKyspIHtcblxuICAgICAgICAgICAga2VybC5pbml0aWFsaXplKCk7XG4gICAgICAgICAgICBrZXJsLnJlc2V0KCk7XG4gICAgICAgICAgICBrZXJsLmFic29yYihoYXNoLCAwLCBoYXNoLmxlbmd0aCk7XG4gICAgICAgICAgICBrZXJsLnNxdWVlemUoaGFzaCwgMCwgQ3VybC5IQVNIX0xFTkdUSCk7XG4gICAgICAgIH1cblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI0MzsgaisrKSB7XG5cbiAgICAgICAgICAgIHNpZ25hdHVyZUZyYWdtZW50W2kgKiAyNDMgKyBqXSA9IGhhc2hbal07XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gc2lnbmF0dXJlRnJhZ21lbnQ7XG59XG5cbi8qKlxuKlxuKlxuKiovXG52YXIgdmFsaWRhdGVTaWduYXR1cmVzID0gZnVuY3Rpb24oZXhwZWN0ZWRBZGRyZXNzLCBzaWduYXR1cmVGcmFnbWVudHMsIGJ1bmRsZUhhc2gpIHtcbiAgICBpZiAoIWJ1bmRsZUhhc2gpIHtcbiAgICAgICAgdGhyb3cgZXJyb3JzLmludmFsaWRCdW5kbGVIYXNoKCk7XG4gICAgfVxuXG4gICAgdmFyIHNlbGYgPSB0aGlzO1xuICAgIHZhciBidW5kbGUgPSBuZXcgQnVuZGxlKCk7XG5cbiAgICB2YXIgbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50cyA9IFtdO1xuICAgIHZhciBub3JtYWxpemVkQnVuZGxlSGFzaCA9IGJ1bmRsZS5ub3JtYWxpemVkQnVuZGxlKGJ1bmRsZUhhc2gpO1xuXG4gICAgLy8gU3BsaXQgaGFzaCBpbnRvIDMgZnJhZ21lbnRzXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCAzOyBpKyspIHtcbiAgICAgICAgbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50c1tpXSA9IG5vcm1hbGl6ZWRCdW5kbGVIYXNoLnNsaWNlKGkgKiAyNywgKGkgKyAxKSAqIDI3KTtcbiAgICB9XG5cbiAgICAvLyBHZXQgZGlnZXN0c1xuICAgIHZhciBkaWdlc3RzID0gW107XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IHNpZ25hdHVyZUZyYWdtZW50cy5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIHZhciBkaWdlc3RCdWZmZXIgPSBkaWdlc3Qobm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50c1tpICUgM10sIENvbnZlcnRlci50cml0cyhzaWduYXR1cmVGcmFnbWVudHNbaV0pKTtcblxuICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IDI0MzsgaisrKSB7XG5cbiAgICAgICAgICAgIGRpZ2VzdHNbaSAqIDI0MyArIGpdID0gZGlnZXN0QnVmZmVyW2pdXG4gICAgICAgIH1cbiAgICB9XG5cbiAgICB2YXIgYWRkcmVzcyA9IENvbnZlcnRlci50cnl0ZXMoc2VsZi5hZGRyZXNzKGRpZ2VzdHMpKTtcblxuICAgIHJldHVybiAoZXhwZWN0ZWRBZGRyZXNzID09PSBhZGRyZXNzKTtcbn1cblxuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgICBrZXkgICAgICAgICAgICAgICAgIDoga2V5LFxuICAgIGRpZ2VzdHMgICAgICAgICAgICAgOiBkaWdlc3RzLFxuICAgIGFkZHJlc3MgICAgICAgICAgICAgOiBhZGRyZXNzLFxuICAgIGRpZ2VzdCAgICAgICAgICAgICAgOiBkaWdlc3QsXG4gICAgc2lnbmF0dXJlRnJhZ21lbnQgICA6IHNpZ25hdHVyZUZyYWdtZW50LFxuICAgIHZhbGlkYXRlU2lnbmF0dXJlcyAgOiB2YWxpZGF0ZVNpZ25hdHVyZXNcbn1cbiIsIlxubW9kdWxlLmV4cG9ydHMgPSB7XG5cbiAgICBpbnZhbGlkVHJ5dGVzOiBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBFcnJvcihcIkludmFsaWQgVHJ5dGVzIHByb3ZpZGVkXCIpO1xuICAgIH0sXG4gICAgaW52YWxpZFNlZWQ6IGZ1bmN0aW9uKCkge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiSW52YWxpZCBTZWVkIHByb3ZpZGVkXCIpO1xuICAgIH0sXG4gICAgaW52YWxpZEluZGV4OiBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBFcnJvcihcIkludmFsaWQgSW5kZXggb3B0aW9uIHByb3ZpZGVkXCIpO1xuICAgIH0sIFxuICAgIGludmFsaWRTZWN1cml0eTogZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBuZXcgRXJyb3IoXCJJbnZhbGlkIFNlY3VyaXR5IG9wdGlvbiBwcm92aWRlZFwiKTtcbiAgICB9LFxuICAgIGludmFsaWRDaGVja3N1bTogZnVuY3Rpb24oYWRkcmVzcykge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiSW52YWxpZCBDaGVja3N1bSBzdXBwbGllZCBmb3IgYWRkcmVzczogXCIgKyBhZGRyZXNzKVxuICAgIH0sXG4gICAgaW52YWxpZEF0dGFjaGVkVHJ5dGVzOiBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBFcnJvcihcIkludmFsaWQgYXR0YWNoZWQgVHJ5dGVzIHByb3ZpZGVkXCIpO1xuICAgIH0sXG4gICAgaW52YWxpZFRyYW5zZmVyczogZnVuY3Rpb24oKSB7XG4gICAgICAgIHJldHVybiBuZXcgRXJyb3IoXCJJbnZhbGlkIHRyYW5zZmVycyBvYmplY3RcIik7XG4gICAgfSxcbiAgICBpbnZhbGlkS2V5OiBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBFcnJvcihcIllvdSBoYXZlIHByb3ZpZGVkIGFuIGludmFsaWQga2V5IHZhbHVlXCIpO1xuICAgIH0sXG4gICAgaW52YWxpZFRydW5rT3JCcmFuY2g6IGZ1bmN0aW9uKGhhc2gpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBFcnJvcihcIllvdSBoYXZlIHByb3ZpZGVkIGFuIGludmFsaWQgaGFzaCBhcyBhIHRydW5rL2JyYW5jaDogXCIgKyBoYXNoKTtcbiAgICB9LFxuICAgIGludmFsaWRVcmk6IGZ1bmN0aW9uKHVyaSkge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiWW91IGhhdmUgcHJvdmlkZWQgYW4gaW52YWxpZCBVUkkgZm9yIHlvdXIgTmVpZ2hib3I6IFwiICsgdXJpKVxuICAgIH0sXG4gICAgbm90SW50OiBmdW5jdGlvbigpIHtcbiAgICAgICAgcmV0dXJuIG5ldyBFcnJvcihcIk9uZSBvZiB5b3VyIGlucHV0cyBpcyBub3QgYW4gaW50ZWdlclwiKTtcbiAgICB9LFxuICAgIGludmFsaWRJbnB1dHM6IGZ1bmN0aW9uKCkge1xuICAgICAgICByZXR1cm4gbmV3IEVycm9yKFwiSW52YWxpZCBpbnB1dHMgcHJvdmlkZWRcIik7XG4gICAgfVxufVxuIiwibW9kdWxlLmV4cG9ydHMgPSB7XG4gIGN1cmw6IHJlcXVpcmUoJy4vY3J5cHRvL2N1cmwvY3VybCcpLFxuICBrZXJsOiByZXF1aXJlKCcuL2NyeXB0by9rZXJsL2tlcmwnKSxcbiAgYnVuZGxlOiByZXF1aXJlKCcuL2NyeXB0by9idW5kbGUvYnVuZGxlJyksXG4gIGNvbnZlcnRlcjogcmVxdWlyZSgnLi9jcnlwdG8vY29udmVydGVyL2NvbnZlcnRlcicpLFxuICBzaWduaW5nOiByZXF1aXJlKCcuL2NyeXB0by9zaWduaW5nL3NpZ25pbmcnKSxcbiAgb2xkU2lnbmluZzogcmVxdWlyZSgnLi9jcnlwdG8vc2lnbmluZy9vbGRTaWduaW5nJyksXG4gIGhtYWM6IHJlcXVpcmUoJy4vY3J5cHRvL2htYWMvaG1hYycpLFxuICBtdWx0aXNpZzogcmVxdWlyZSgnLi9tdWx0aXNpZy9tdWx0aXNpZycpLFxuICB1dGlsczogcmVxdWlyZShcIi4vdXRpbHMvdXRpbHNcIiksXG4gIHZhbGlkOiByZXF1aXJlKFwiLi9lcnJvcnMvaW5wdXRFcnJvcnNcIiksXG4gIGFkZDogcmVxdWlyZShcIi4vY3J5cHRvL2hlbHBlcnMvYWRkZXJcIilcbn1cbiIsInZhciBDb252ZXJ0ZXIgICAgICA9ICByZXF1aXJlKCcuLi9jcnlwdG8vY29udmVydGVyL2NvbnZlcnRlcicpO1xudmFyIEN1cmwgICAgICAgICAgID0gIHJlcXVpcmUoJy4uL2NyeXB0by9jdXJsL2N1cmwnKTtcbnZhciBLZXJsICAgICAgICAgICA9ICByZXF1aXJlKCcuLi9jcnlwdG8va2VybC9rZXJsJyk7XG52YXIgU2lnbmluZyAgICAgICAgPSAgcmVxdWlyZSgnLi4vY3J5cHRvL3NpZ25pbmcvc2lnbmluZycpO1xudmFyIFV0aWxzICAgICAgICAgID0gIHJlcXVpcmUoJy4uL3V0aWxzL3V0aWxzJyk7XG52YXIgaW5wdXRWYWxpZGF0b3IgPSAgcmVxdWlyZSgnLi4vdXRpbHMvaW5wdXRWYWxpZGF0b3InKTtcblxuXG4vKipcbiogICBJbml0aWFsaXplcyBhIG5ldyBtdWx0aXNpZyBhZGRyZXNzXG4qXG4qICAgQG1ldGhvZCBhZGREaWdlc3RcbiogICBAcGFyYW0ge3N0cmluZ3xhcnJheX0gZGlnZXN0IGRpZ2VzdCB0cnl0ZXNcbiogICBAcmV0dXJuIHtvYmplY3R9IGFkZHJlc3MgaW5zdGFuY2VcbipcbioqL1xuZnVuY3Rpb24gQWRkcmVzcyhkaWdlc3RzKSB7XG5cbiAgaWYgKCEodGhpcyBpbnN0YW5jZW9mIEFkZHJlc3MpKSB7XG4gICAgcmV0dXJuIG5ldyBBZGRyZXNzKGRpZ2VzdHMpO1xuICB9XG5cbiAgLy8gSW5pdGlhbGl6ZSBrZXJsIGluc3RhbmNlXG4gIHRoaXMuX2tlcmwgPSBuZXcgS2VybCgpO1xuICB0aGlzLl9rZXJsLmluaXRpYWxpemUoKTtcblxuXG4gIC8vIEFkZCBkaWdlc3RzIGlmIGFueVxuICBpZiAoZGlnZXN0cykge1xuXG4gICAgdGhpcy5hYnNvcmIoZGlnZXN0cyk7XG4gIH1cbn1cblxuLyoqXG4qICAgQWJzb3JicyBrZXkgZGlnZXN0c1xuKlxuKiAgIEBtZXRob2QgYWJzb3JiXG4qICAgQHBhcmFtIHtzdHJpbmd8YXJyYXl9IGRpZ2VzdCBkaWdlc3QgdHJ5dGVzXG4qICAgQHJldHVybiB7b2JqZWN0fSBhZGRyZXNzIGluc3RhbmNlXG4qXG4qKi9cbkFkZHJlc3MucHJvdG90eXBlLmFic29yYiA9IGZ1bmN0aW9uIChkaWdlc3QpIHtcblxuICAvLyBDb25zdHJ1Y3QgYXJyYXlcbiAgdmFyIGRpZ2VzdHMgPSBBcnJheS5pc0FycmF5KGRpZ2VzdCkgPyBkaWdlc3QgOiBbZGlnZXN0XTtcblxuICAvLyBBZGQgZGlnZXN0c1xuICBmb3IgKHZhciBpID0gMDsgaSA8IGRpZ2VzdHMubGVuZ3RoOyBpKyspIHtcblxuICAgIC8vIEdldCB0cml0cyBvZiBkaWdlc3RcbiAgICB2YXIgZGlnZXN0VHJpdHMgPSBDb252ZXJ0ZXIudHJpdHMoZGlnZXN0c1tpXSk7XG5cbiAgICAvLyBBYnNvcmIgZGlnZXN0XG4gICAgdGhpcy5fa2VybC5hYnNvcmIoZGlnZXN0VHJpdHMsIDAsIGRpZ2VzdFRyaXRzLmxlbmd0aCk7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn1cblxuLyoqXG4qICAgRmluYWxpemVzIGFuZCByZXR1cm5zIHRoZSBtdWx0aXNpZyBhZGRyZXNzIGluIHRyeXRlc1xuKlxuKiAgIEBtZXRob2QgZmluYWxpemVcbiogICBAcGFyYW0ge3N0cmluZ30gZGlnZXN0IGRpZ2VzdCB0cnl0ZXMsIG9wdGlvbmFsXG4qICAgQHJldHVybiB7c3RyaW5nfSBhZGRyZXNzIHRyeXRlc1xuKlxuKiovXG5BZGRyZXNzLnByb3RvdHlwZS5maW5hbGl6ZSA9IGZ1bmN0aW9uIChkaWdlc3QpIHtcblxuICAgIC8vIEFic29yYiBsYXN0IGRpZ2VzdCBpZiBwcm92aWRlZFxuICAgIGlmIChkaWdlc3QpIHtcbiAgICAgIHRoaXMuYWJzb3JiKGRpZ2VzdCk7XG4gICAgfVxuXG4gICAgLy8gU3F1ZWV6ZSB0aGUgYWRkcmVzcyB0cml0c1xuICAgIHZhciBhZGRyZXNzVHJpdHMgPSBbXTtcbiAgICB0aGlzLl9rZXJsLnNxdWVlemUoYWRkcmVzc1RyaXRzLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcblxuICAgIC8vIENvbnZlcnQgdHJpdHMgaW50byB0cnl0ZXMgYW5kIHJldHVybiB0aGUgYWRkcmVzc1xuICAgIHJldHVybiBDb252ZXJ0ZXIudHJ5dGVzKGFkZHJlc3NUcml0cyk7XG59XG5cblxubW9kdWxlLmV4cG9ydHMgPSBBZGRyZXNzO1xuIiwidmFyIFNpZ25pbmcgICAgICAgICA9ICByZXF1aXJlKCcuLi9jcnlwdG8vc2lnbmluZy9zaWduaW5nJyk7XG52YXIgQ29udmVydGVyICAgICAgID0gIHJlcXVpcmUoJy4uL2NyeXB0by9jb252ZXJ0ZXIvY29udmVydGVyJyk7XG52YXIgS2VybCAgICAgICAgICAgID0gIHJlcXVpcmUoJy4uL2NyeXB0by9rZXJsL2tlcmwnKTtcbnZhciBDdXJsICAgICAgICAgICAgPSAgcmVxdWlyZSgnLi4vY3J5cHRvL2N1cmwvY3VybCcpO1xudmFyIEJ1bmRsZSAgICAgICAgICA9ICByZXF1aXJlKCcuLi9jcnlwdG8vYnVuZGxlL2J1bmRsZScpO1xudmFyIFV0aWxzICAgICAgICAgICA9ICByZXF1aXJlKCcuLi91dGlscy91dGlscycpO1xudmFyIGlucHV0VmFsaWRhdG9yICA9ICByZXF1aXJlKCcuLi91dGlscy9pbnB1dFZhbGlkYXRvcicpO1xudmFyIGVycm9ycyAgICAgICAgICA9ICByZXF1aXJlKCcuLi9lcnJvcnMvaW5wdXRFcnJvcnMnKTtcbnZhciBBZGRyZXNzICAgICAgICAgPSAgcmVxdWlyZSgnLi9hZGRyZXNzJyk7XG5cbmZ1bmN0aW9uIE11bHRpc2lnKHByb3ZpZGVyKSB7XG5cbiAgICB0aGlzLl9tYWtlUmVxdWVzdCA9IHByb3ZpZGVyO1xufVxuXG5cbi8qKlxuKiAgIEdldHMgdGhlIGtleSB2YWx1ZSBvZiBhIHNlZWRcbipcbiogICBAbWV0aG9kIGdldEtleVxuKiAgIEBwYXJhbSB7c3RyaW5nfSBzZWVkXG4qICAgQHBhcmFtIHtpbnR9IGluZGV4XG4qICAgQHBhcmFtIHtpbnR9IHNlY3VyaXR5IFNlY3VyaXR5IGxldmVsIHRvIGJlIHVzZWQgZm9yIHRoZSBwcml2YXRlIGtleSAvIGFkZHJlc3MuIENhbiBiZSAxLCAyIG9yIDNcbiogICBAcmV0dXJucyB7c3RyaW5nfSBkaWdlc3QgdHJ5dGVzXG4qKi9cbk11bHRpc2lnLmdldEtleSA9IGZ1bmN0aW9uKHNlZWQsIGluZGV4LCBzZWN1cml0eSkge1xuXG4gICAgcmV0dXJuIENvbnZlcnRlci50cnl0ZXMoU2lnbmluZy5rZXkoQ29udmVydGVyLnRyaXRzKHNlZWQpLCBpbmRleCwgc2VjdXJpdHkpKTtcbn1cblxuLyoqXG4qICAgR2V0cyB0aGUgZGlnZXN0IHZhbHVlIG9mIGEgc2VlZFxuKlxuKiAgIEBtZXRob2QgZ2V0RGlnZXN0XG4qICAgQHBhcmFtIHtzdHJpbmd9IHNlZWRcbiogICBAcGFyYW0ge2ludH0gaW5kZXhcbiogICBAcGFyYW0ge2ludH0gc2VjdXJpdHkgU2VjdXJpdHkgbGV2ZWwgdG8gYmUgdXNlZCBmb3IgdGhlIHByaXZhdGUga2V5IC8gYWRkcmVzcy4gQ2FuIGJlIDEsIDIgb3IgM1xuKiAgIEByZXR1cm5zIHtzdHJpbmd9IGRpZ2VzdCB0cnl0ZXNcbioqL1xuTXVsdGlzaWcuZ2V0RGlnZXN0ID0gZnVuY3Rpb24oc2VlZCwgaW5kZXgsIHNlY3VyaXR5KSB7XG5cbiAgICB2YXIga2V5ID0gU2lnbmluZy5rZXkoQ29udmVydGVyLnRyaXRzKHNlZWQpLCBpbmRleCwgc2VjdXJpdHkpO1xuICAgIHJldHVybiBDb252ZXJ0ZXIudHJ5dGVzKFNpZ25pbmcuZGlnZXN0cyhrZXkpKTtcbn1cblxuLyoqXG4qICAgTXVsdGlzaWcgYWRkcmVzcyBjb25zdHJ1Y3RvclxuKi9cbk11bHRpc2lnLmFkZHJlc3MgPSBBZGRyZXNzO1xuXG4vKipcbiogICBWYWxpZGF0ZXMgIGEgZ2VuZXJhdGVkIG11bHRpc2lnIGFkZHJlc3NcbipcbiogICBAbWV0aG9kIHZhbGlkYXRlQWRkcmVzc1xuKiAgIEBwYXJhbSB7c3RyaW5nfSBtdWx0aXNpZ0FkZHJlc3NcbiogICBAcGFyYW0ge2FycmF5fSBkaWdlc3RzXG4qICAgQHJldHVybnMge2Jvb2x9XG4qKi9cbk11bHRpc2lnLnZhbGlkYXRlQWRkcmVzcyA9IGZ1bmN0aW9uKG11bHRpc2lnQWRkcmVzcywgZGlnZXN0cykge1xuXG4gICAgdmFyIGtlcmwgPSBuZXcgS2VybCgpO1xuXG4gICAgLy8gaW5pdGlhbGl6ZSBLZXJsIHdpdGggdGhlIHByb3ZpZGVkIHN0YXRlXG4gICAga2VybC5pbml0aWFsaXplKCk7XG5cbiAgICAvLyBBYnNvcmIgYWxsIGtleSBkaWdlc3RzXG4gICAgZGlnZXN0cy5mb3JFYWNoKGZ1bmN0aW9uKGtleURpZ2VzdCkge1xuICAgICAgICB2YXIgdHJpdHMgPSBDb252ZXJ0ZXIudHJpdHMoa2V5RGlnZXN0KTtcbiAgICAgICAga2VybC5hYnNvcmIoQ29udmVydGVyLnRyaXRzKGtleURpZ2VzdCksIDAsIHRyaXRzLmxlbmd0aCk7XG4gICAgfSlcblxuICAgIC8vIFNxdWVlemUgYWRkcmVzcyB0cml0c1xuICAgIHZhciBhZGRyZXNzVHJpdHMgPSBbXTtcbiAgICBrZXJsLnNxdWVlemUoYWRkcmVzc1RyaXRzLCAwLCBDdXJsLkhBU0hfTEVOR1RIKTtcblxuICAgIC8vIENvbnZlcnQgdHJpdHMgaW50byB0cnl0ZXMgYW5kIHJldHVybiB0aGUgYWRkcmVzc1xuICAgIHJldHVybiBDb252ZXJ0ZXIudHJ5dGVzKGFkZHJlc3NUcml0cykgPT09IG11bHRpc2lnQWRkcmVzcztcbn1cblxuXG4vKipcbiogICBQcmVwYXJlcyB0cmFuc2ZlciBieSBnZW5lcmF0aW5nIHRoZSBidW5kbGUgd2l0aCB0aGUgY29ycmVzcG9uZGluZyBjb3NpZ25lciB0cmFuc2FjdGlvbnNcbiogICBEb2VzIG5vdCBjb250YWluIHNpZ25hdHVyZXNcbipcbiogICBAbWV0aG9kIGluaXRpYXRlVHJhbnNmZXJcbiogICBAcGFyYW0ge29iamVjdH0gaW5wdXQgdGhlIGlucHV0IGFkZHJlc3NlcyBhcyB3ZWxsIGFzIHRoZSBzZWN1cml0eVN1bSwgYW5kIGJhbGFuY2VcbiogICAgICAgICAgICAgICAgICAgd2hlcmUgYGFkZHJlc3NgIGlzIHRoZSBpbnB1dCBtdWx0aXNpZyBhZGRyZXNzXG4qICAgICAgICAgICAgICAgICAgIGFuZCBgc2VjdXJpdHlTdW1gIGlzIHRoZSBzdW0gb2Ygc2VjdXJpdHkgbGV2ZWxzIHVzZWQgYnkgYWxsIGNvLXNpZ25lcnNcbiogICAgICAgICAgICAgICAgICAgYW5kIGBiYWxhbmNlYCBpcyB0aGUgZXhwZWN0ZWQgYmFsYW5jZSwgaWYgeW91IHdpc2ggdG8gb3ZlcnJpZGUgZ2V0QmFsYW5jZXNcbiogICBAcGFyYW0ge3N0cmluZ30gcmVtYWluZGVyQWRkcmVzcyBIYXMgdG8gYmUgZ2VuZXJhdGVkIGJ5IHRoZSBjb3NpZ25lcnMgYmVmb3JlIGluaXRpYXRpbmcgdGhlIHRyYW5zZmVyLCBjYW4gYmUgbnVsbCBpZiBmdWxseSBzcGVudFxuKiAgIEBwYXJhbSB7b2JqZWN0fSB0cmFuc2ZlcnNcbiogICBAcGFyYW0ge2Z1bmN0aW9ufSBjYWxsYmFja1xuKiAgIEByZXR1cm5zIHthcnJheX0gQXJyYXkgb2YgdHJhbnNhY3Rpb24gb2JqZWN0c1xuKiovXG5NdWx0aXNpZy5pbml0aWF0ZVRyYW5zZmVyID0gZnVuY3Rpb24oaW5wdXQsIHJlbWFpbmRlckFkZHJlc3MsIHRyYW5zZmVycywgY2FsbGJhY2spIHtcblxuICAgIHZhciBzZWxmID0gdGhpcztcblxuICAgIC8vIElmIG1lc3NhZ2Ugb3IgdGFnIGlzIG5vdCBzdXBwbGllZCwgcHJvdmlkZSBpdFxuICAgIC8vIEFsc28gcmVtb3ZlIHRoZSBjaGVja3N1bSBvZiB0aGUgYWRkcmVzcyBpZiBpdCdzIHRoZXJlXG4gICAgdHJhbnNmZXJzLmZvckVhY2goZnVuY3Rpb24odGhpc1RyYW5zZmVyKSB7XG4gICAgICAgIHRoaXNUcmFuc2Zlci5tZXNzYWdlID0gdGhpc1RyYW5zZmVyLm1lc3NhZ2UgPyB0aGlzVHJhbnNmZXIubWVzc2FnZSA6ICcnO1xuICAgICAgICB0aGlzVHJhbnNmZXIudGFnID0gdGhpc1RyYW5zZmVyLnRhZyA/IHRoaXNUcmFuc2Zlci50YWcgOiAnJztcbiAgICAgICAgdGhpc1RyYW5zZmVyLm9ic29sZXRlVGFnID0gdGhpc1RyYW5zZmVyLm9ic29sZXRlVGFnID8gdGhpc1RyYW5zZmVyLm9ic29sZXRlVGFnIDogJyc7ICAgICAgICBcbiAgICAgICAgdGhpc1RyYW5zZmVyLmFkZHJlc3MgPSBVdGlscy5ub0NoZWNrc3VtKHRoaXNUcmFuc2Zlci5hZGRyZXNzKTtcbiAgICB9KVxuXG4gICAgLy8gSW5wdXQgdmFsaWRhdGlvbiBvZiB0cmFuc2ZlcnMgb2JqZWN0XG4gICAgaWYgKCFpbnB1dFZhbGlkYXRvci5pc1RyYW5zZmVyc0FycmF5KHRyYW5zZmVycykpIHtcbiAgICAgICAgcmV0dXJuIGNhbGxiYWNrKGVycm9ycy5pbnZhbGlkVHJhbnNmZXJzKCkpO1xuICAgIH1cblxuICAgIC8vIGNoZWNrIGlmIGludFxuICAgIGlmICghaW5wdXRWYWxpZGF0b3IuaXNWYWx1ZShpbnB1dC5zZWN1cml0eVN1bSkpIHtcbiAgICAgICAgcmV0dXJuIGNhbGxiYWNrKGVycm9ycy5pbnZhbGlkSW5wdXRzKCkpO1xuICAgIH1cblxuICAgIC8vIHZhbGlkYXRlIGlucHV0IGFkZHJlc3NcbiAgICBpZiAoIWlucHV0VmFsaWRhdG9yLmlzQWRkcmVzcyhpbnB1dC5hZGRyZXNzKSkge1xuICAgICAgICByZXR1cm4gY2FsbGJhY2soZXJyb3JzLmludmFsaWRUcnl0ZXMoKSk7XG4gICAgfVxuXG4gICAgLy8gdmFsaWRhdGUgcmVtYWluZGVyIGFkZHJlc3NcbiAgICBpZiAocmVtYWluZGVyQWRkcmVzcyAmJiAhaW5wdXRWYWxpZGF0b3IuaXNBZGRyZXNzKHJlbWFpbmRlckFkZHJlc3MpKSB7XG4gICAgICAgIHJldHVybiBjYWxsYmFjayhlcnJvcnMuaW52YWxpZFRyeXRlcygpKTtcbiAgICB9XG5cbiAgICAvLyBDcmVhdGUgYSBuZXcgYnVuZGxlXG4gICAgdmFyIGJ1bmRsZSA9IG5ldyBCdW5kbGUoKTtcblxuICAgIHZhciB0b3RhbFZhbHVlID0gMDtcbiAgICB2YXIgc2lnbmF0dXJlRnJhZ21lbnRzID0gW107XG4gICAgdmFyIHRhZztcblxuICAgIC8vXG4gICAgLy8gIEl0ZXJhdGUgb3ZlciBhbGwgdHJhbnNmZXJzLCBnZXQgdG90YWxWYWx1ZVxuICAgIC8vICBhbmQgcHJlcGFyZSB0aGUgc2lnbmF0dXJlRnJhZ21lbnRzLCBtZXNzYWdlIGFuZCB0YWdcbiAgICAvL1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdHJhbnNmZXJzLmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgdmFyIHNpZ25hdHVyZU1lc3NhZ2VMZW5ndGggPSAxO1xuXG4gICAgICAgIC8vIElmIG1lc3NhZ2UgbG9uZ2VyIHRoYW4gMjE4NyB0cnl0ZXMsIGluY3JlYXNlIHNpZ25hdHVyZU1lc3NhZ2VMZW5ndGggKGFkZCBtdWx0aXBsZSB0cmFuc2FjdGlvbnMpXG4gICAgICAgIGlmICh0cmFuc2ZlcnNbaV0ubWVzc2FnZS5sZW5ndGggPiAyMTg3KSB7XG5cbiAgICAgICAgICAgIC8vIEdldCB0b3RhbCBsZW5ndGgsIG1lc3NhZ2UgLyBtYXhMZW5ndGggKDIxODcgdHJ5dGVzKVxuICAgICAgICAgICAgc2lnbmF0dXJlTWVzc2FnZUxlbmd0aCArPSBNYXRoLmZsb29yKHRyYW5zZmVyc1tpXS5tZXNzYWdlLmxlbmd0aCAvIDIxODcpO1xuXG4gICAgICAgICAgICB2YXIgbXNnQ29weSA9IHRyYW5zZmVyc1tpXS5tZXNzYWdlO1xuXG4gICAgICAgICAgICAvLyBXaGlsZSB0aGVyZSBpcyBzdGlsbCBhIG1lc3NhZ2UsIGNvcHkgaXRcbiAgICAgICAgICAgIHdoaWxlIChtc2dDb3B5KSB7XG5cbiAgICAgICAgICAgICAgICB2YXIgZnJhZ21lbnQgPSBtc2dDb3B5LnNsaWNlKDAsIDIxODcpO1xuICAgICAgICAgICAgICAgIG1zZ0NvcHkgPSBtc2dDb3B5LnNsaWNlKDIxODcsIG1zZ0NvcHkubGVuZ3RoKTtcblxuICAgICAgICAgICAgICAgIC8vIFBhZCByZW1haW5kZXIgb2YgZnJhZ21lbnRcbiAgICAgICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgZnJhZ21lbnQubGVuZ3RoIDwgMjE4NzsgaisrKSB7XG4gICAgICAgICAgICAgICAgICAgIGZyYWdtZW50ICs9ICc5JztcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBzaWduYXR1cmVGcmFnbWVudHMucHVzaChmcmFnbWVudCk7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIC8vIEVsc2UsIGdldCBzaW5nbGUgZnJhZ21lbnQgd2l0aCAyMTg3IG9mIDkncyB0cnl0ZXNcbiAgICAgICAgICAgIHZhciBmcmFnbWVudCA9ICcnO1xuXG4gICAgICAgICAgICBpZiAodHJhbnNmZXJzW2ldLm1lc3NhZ2UpIHtcbiAgICAgICAgICAgICAgICBmcmFnbWVudCA9IHRyYW5zZmVyc1tpXS5tZXNzYWdlLnNsaWNlKDAsIDIxODcpXG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGZvciAodmFyIGogPSAwOyBmcmFnbWVudC5sZW5ndGggPCAyMTg3OyBqKyspIHtcbiAgICAgICAgICAgICAgICBmcmFnbWVudCArPSAnOSc7XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIHNpZ25hdHVyZUZyYWdtZW50cy5wdXNoKGZyYWdtZW50KTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIGdldCBjdXJyZW50IHRpbWVzdGFtcCBpbiBzZWNvbmRzXG4gICAgICAgIHZhciB0aW1lc3RhbXAgPSBNYXRoLmZsb29yKERhdGUubm93KCkgLyAxMDAwKTtcblxuICAgICAgICAvLyBJZiBubyB0YWcgZGVmaW5lZCwgZ2V0IDI3IHRyeXRlIHRhZy5cbiAgICAgICAgdGFnID0gdHJhbnNmZXJzW2ldLnRhZyA/IHRyYW5zZmVyc1tpXS50YWcgOiAnOTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5OTk5JztcblxuICAgICAgICAvLyBQYWQgZm9yIHJlcXVpcmVkIDI3IHRyeXRlIGxlbmd0aFxuICAgICAgICBmb3IgKHZhciBqID0gMDsgdGFnLmxlbmd0aCA8IDI3OyBqKyspIHtcbiAgICAgICAgICAgIHRhZyArPSAnOSc7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBBZGQgZmlyc3QgZW50cmllcyB0byB0aGUgYnVuZGxlXG4gICAgICAgIC8vIFNsaWNlIHRoZSBhZGRyZXNzIGluIGNhc2UgdGhlIHVzZXIgcHJvdmlkZWQgYSBjaGVja3N1bW1lZCBvbmVcbiAgICAgICAgYnVuZGxlLmFkZEVudHJ5KHNpZ25hdHVyZU1lc3NhZ2VMZW5ndGgsIHRyYW5zZmVyc1tpXS5hZGRyZXNzLnNsaWNlKDAsIDgxKSwgdHJhbnNmZXJzW2ldLnZhbHVlLCB0YWcsIHRpbWVzdGFtcCk7XG5cbiAgICAgICAgLy8gU3VtIHVwIHRvdGFsIHZhbHVlXG4gICAgICAgIHRvdGFsVmFsdWUgKz0gcGFyc2VJbnQodHJhbnNmZXJzW2ldLnZhbHVlKTtcbiAgICB9XG5cbiAgICAvLyBHZXQgaW5wdXRzIGlmIHdlIGFyZSBzZW5kaW5nIHRva2Vuc1xuICAgIGlmICh0b3RhbFZhbHVlKSB7XG5cbiAgICAgICAgZnVuY3Rpb24gY3JlYXRlQnVuZGxlKHRvdGFsQmFsYW5jZSwgY2FsbGJhY2spIHtcbiAgICAgICAgICAgIGlmICh0b3RhbEJhbGFuY2UgPiAwKSB7XG5cbiAgICAgICAgICAgICAgICB2YXIgdG9TdWJ0cmFjdCA9IDAgLSB0b3RhbEJhbGFuY2U7XG4gICAgICAgICAgICAgICAgdmFyIHRpbWVzdGFtcCA9IE1hdGguZmxvb3IoRGF0ZS5ub3coKSAvIDEwMDApO1xuXG4gICAgICAgICAgICAgICAgLy8gQWRkIGlucHV0IGFzIGJ1bmRsZSBlbnRyeVxuICAgICAgICAgICAgICAgIC8vIE9ubHkgYSBzaW5nbGUgZW50cnksIHNpZ25hdHVyZXMgd2lsbCBiZSBhZGRlZCBsYXRlclxuICAgICAgICAgICAgICAgIGJ1bmRsZS5hZGRFbnRyeShpbnB1dC5zZWN1cml0eVN1bSwgaW5wdXQuYWRkcmVzcywgdG9TdWJ0cmFjdCwgdGFnLCB0aW1lc3RhbXApO1xuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICBpZiAodG90YWxWYWx1ZSA+IHRvdGFsQmFsYW5jZSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBjYWxsYmFjayhuZXcgRXJyb3IoXCJOb3QgZW5vdWdoIGJhbGFuY2UuXCIpKTtcbiAgICAgICAgICAgIH1cblxuXG4gICAgICAgICAgICAvLyBJZiB0aGVyZSBpcyBhIHJlbWFpbmRlciB2YWx1ZVxuICAgICAgICAgICAgLy8gQWRkIGV4dHJhIG91dHB1dCB0byBzZW5kIHJlbWFpbmluZyBmdW5kcyB0b1xuICAgICAgICAgICAgaWYgKHRvdGFsQmFsYW5jZSA+IHRvdGFsVmFsdWUpIHtcblxuICAgICAgICAgICAgICAgIHZhciByZW1haW5kZXIgPSB0b3RhbEJhbGFuY2UgLSB0b3RhbFZhbHVlO1xuXG4gICAgICAgICAgICAgICAgLy8gUmVtYWluZGVyIGJ1bmRsZSBlbnRyeSBpZiBuZWNlc3NhcnlcbiAgICAgICAgICAgICAgICBpZiAoIXJlbWFpbmRlckFkZHJlc3MpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIGNhbGxiYWNrKG5ldyBFcnJvcihcIk5vIHJlbWFpbmRlciBhZGRyZXNzIGRlZmluZWRcIikpO1xuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGJ1bmRsZS5hZGRFbnRyeSgxLCByZW1haW5kZXJBZGRyZXNzLCByZW1haW5kZXIsIHRhZywgdGltZXN0YW1wKTtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgYnVuZGxlLmZpbmFsaXplKCk7XG4gICAgICAgICAgICBidW5kbGUuYWRkVHJ5dGVzKHNpZ25hdHVyZUZyYWdtZW50cyk7XG5cbiAgICAgICAgICAgIHJldHVybiBjYWxsYmFjayhudWxsLCBidW5kbGUuYnVuZGxlKTtcbiAgICAgICAgfTtcblxuICAgICAgICBpZiAoaW5wdXQuYmFsYW5jZSkge1xuICAgICAgICAgIGNyZWF0ZUJ1bmRsZShpbnB1dC5iYWxhbmNlLCBjYWxsYmFjayk7XG4gICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgdmFyIGNvbW1hbmQgPSB7XG4gICAgICAgICAgICAgICdjb21tYW5kJzogJ2dldEJhbGFuY2VzJyxcbiAgICAgICAgICAgICAgJ2FkZHJlc3Nlcyc6IG5ldyBBcnJheShpbnB1dC5hZGRyZXNzKSxcbiAgICAgICAgICAgICAgJ3RocmVzaG9sZCc6IDEwMFxuICAgICAgICAgIH1cbiAgICAgICAgICBzZWxmLl9tYWtlUmVxdWVzdC5zZW5kKGNvbW1hbmQsIGZ1bmN0aW9uKGUsIGJhbGFuY2VzKSB7XG4gICAgICAgICAgICAgIGlmIChlKSByZXR1cm4gY2FsbGJhY2soZSk7XG4gICAgICAgICAgICAgIGNyZWF0ZUJ1bmRsZShwYXJzZUludChiYWxhbmNlcy5iYWxhbmNlc1swXSksIGNhbGxiYWNrKTtcbiAgICAgICAgICB9KTtcbiAgICAgICAgfVxuXG4gICAgfSBlbHNlIHtcblxuICAgICAgICByZXR1cm4gY2FsbGJhY2sobmV3IEVycm9yKFwiSW52YWxpZCB2YWx1ZSB0cmFuc2ZlcjogdGhlIHRyYW5zZmVyIGRvZXMgbm90IHJlcXVpcmUgYSBzaWduYXR1cmUuXCIpKTtcbiAgICB9XG5cbn1cblxuXG4vKipcbiogICBBZGRzIHRoZSBjb3NpZ25lciBzaWduYXR1cmVzIHRvIHRoZSBjb3JyZXNwb25kaW5nIGJ1bmRsZSB0cmFuc2FjdGlvblxuKlxuKiAgIEBtZXRob2QgYWRkU2lnbmF0dXJlXG4qICAgQHBhcmFtIHthcnJheX0gYnVuZGxlVG9TaWduXG4qICAgQHBhcmFtIHtpbnR9IGNvc2lnbmVySW5kZXhcbiogICBAcGFyYW0ge3N0cmluZ30gaW5wdXRBZGRyZXNzXG4qICAgQHBhcmFtIHtzdHJpbmd9IGtleVxuKiAgIEBwYXJhbSB7ZnVuY3Rpb259IGNhbGxiYWNrXG4qICAgQHJldHVybnMge2FycmF5fSB0cnl0ZXMgUmV0dXJucyBidW5kbGUgdHJ5dGVzXG4qKi9cbk11bHRpc2lnLmFkZFNpZ25hdHVyZSA9IGZ1bmN0aW9uKGJ1bmRsZVRvU2lnbiwgaW5wdXRBZGRyZXNzLCBrZXksIGNhbGxiYWNrKSB7XG5cbiAgICB2YXIgYnVuZGxlID0gbmV3IEJ1bmRsZSgpO1xuICAgIGJ1bmRsZS5idW5kbGUgPSBidW5kbGVUb1NpZ247XG5cbiAgICAvLyBHZXQgdGhlIHNlY3VyaXR5IHVzZWQgZm9yIHRoZSBwcml2YXRlIGtleVxuICAgIC8vIDEgc2VjdXJpdHkgbGV2ZWwgPSAyMTg3IHRyeXRlc1xuICAgIHZhciBzZWN1cml0eSA9IChrZXkubGVuZ3RoIC8gMjE4Nyk7XG5cbiAgICAvLyBjb252ZXJ0IHByaXZhdGUga2V5IHRyeXRlcyBpbnRvIHRyaXRzXG4gICAgdmFyIGtleSA9IENvbnZlcnRlci50cml0cyhrZXkpO1xuXG5cbiAgICAvLyBGaXJzdCBnZXQgdGhlIHRvdGFsIG51bWJlciBvZiBhbHJlYWR5IHNpZ25lZCB0cmFuc2FjdGlvbnNcbiAgICAvLyB1c2UgdGhhdCBmb3IgdGhlIGJ1bmRsZSBoYXNoIGNhbGN1bGF0aW9uIGFzIHdlbGwgYXMga25vd2luZ1xuICAgIC8vIHdoZXJlIHRvIGFkZCB0aGUgc2lnbmF0dXJlXG4gICAgdmFyIG51bVNpZ25lZFR4cyA9IDA7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ1bmRsZS5idW5kbGUubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICBpZiAoYnVuZGxlLmJ1bmRsZVtpXS5hZGRyZXNzID09PSBpbnB1dEFkZHJlc3MpIHtcblxuICAgICAgICAgICAgLy8gSWYgdHJhbnNhY3Rpb24gaXMgYWxyZWFkeSBzaWduZWQsIGluY3JlYXNlIGNvdW50ZXJcbiAgICAgICAgICAgIGlmICghaW5wdXRWYWxpZGF0b3IuaXNOaW5lc1RyeXRlcyhidW5kbGUuYnVuZGxlW2ldLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudCkpIHtcblxuICAgICAgICAgICAgICAgIG51bVNpZ25lZFR4cysrO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgLy8gRWxzZSBzaWduIHRoZSB0cmFuc2FjdGlvbnNlXG4gICAgICAgICAgICBlbHNlIHtcblxuICAgICAgICAgICAgICAgIHZhciBidW5kbGVIYXNoID0gYnVuZGxlLmJ1bmRsZVtpXS5idW5kbGU7XG5cbiAgICAgICAgICAgICAgICAvLyAgRmlyc3QgNjU2MSB0cml0cyBmb3IgdGhlIGZpcnN0RnJhZ21lbnRcbiAgICAgICAgICAgICAgICB2YXIgZmlyc3RGcmFnbWVudCA9IGtleS5zbGljZSgwLCA2NTYxKTtcblxuICAgICAgICAgICAgICAgIC8vICBHZXQgdGhlIG5vcm1hbGl6ZWQgYnVuZGxlIGhhc2hcbiAgICAgICAgICAgICAgICB2YXIgbm9ybWFsaXplZEJ1bmRsZUhhc2ggPSBidW5kbGUubm9ybWFsaXplZEJ1bmRsZShidW5kbGVIYXNoKTtcbiAgICAgICAgICAgICAgICB2YXIgbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50cyA9IFtdO1xuXG4gICAgICAgICAgICAgICAgLy8gU3BsaXQgaGFzaCBpbnRvIDMgZnJhZ21lbnRzXG4gICAgICAgICAgICAgICAgZm9yICh2YXIgayA9IDA7IGsgPCAzOyBrKyspIHtcbiAgICAgICAgICAgICAgICAgICAgbm9ybWFsaXplZEJ1bmRsZUZyYWdtZW50c1trXSA9IG5vcm1hbGl6ZWRCdW5kbGVIYXNoLnNsaWNlKGsgKiAyNywgKGsgKyAxKSAqIDI3KTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICAvLyAgRmlyc3QgYnVuZGxlIGZyYWdtZW50IHVzZXMgMjcgdHJ5dGVzXG4gICAgICAgICAgICAgICAgdmFyIGZpcnN0QnVuZGxlRnJhZ21lbnQgPSBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRzW251bVNpZ25lZFR4cyAlIDNdO1xuXG4gICAgICAgICAgICAgICAgLy8gIENhbGN1bGF0ZSB0aGUgbmV3IHNpZ25hdHVyZUZyYWdtZW50IHdpdGggdGhlIGZpcnN0IGJ1bmRsZSBmcmFnbWVudFxuICAgICAgICAgICAgICAgIHZhciBmaXJzdFNpZ25lZEZyYWdtZW50ID0gU2lnbmluZy5zaWduYXR1cmVGcmFnbWVudChmaXJzdEJ1bmRsZUZyYWdtZW50LCBmaXJzdEZyYWdtZW50KTtcblxuICAgICAgICAgICAgICAgIC8vICBDb252ZXJ0IHNpZ25hdHVyZSB0byB0cnl0ZXMgYW5kIGFzc2lnbiB0aGUgbmV3IHNpZ25hdHVyZUZyYWdtZW50XG4gICAgICAgICAgICAgICAgYnVuZGxlLmJ1bmRsZVtpXS5zaWduYXR1cmVNZXNzYWdlRnJhZ21lbnQgPSBDb252ZXJ0ZXIudHJ5dGVzKGZpcnN0U2lnbmVkRnJhZ21lbnQpO1xuXG4gICAgICAgICAgICAgICAgZm9yICh2YXIgaiA9IDE7IGogPCBzZWN1cml0eTsgaisrKSB7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gIE5leHQgNjU2MSB0cml0cyBmb3IgdGhlIGZpcnN0RnJhZ21lbnRcbiAgICAgICAgICAgICAgICAgICAgdmFyIG5leHRGcmFnbWVudCA9IGtleS5zbGljZSg2NTYxICogaiwgKGogKyAxKSAqIDY1NjEpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vICBVc2UgdGhlIG5leHQgMjcgdHJ5dGVzXG4gICAgICAgICAgICAgICAgICAgIHZhciBuZXh0QnVuZGxlRnJhZ21lbnQgPSBub3JtYWxpemVkQnVuZGxlRnJhZ21lbnRzWyhudW1TaWduZWRUeHMgKyBqKSAlIDNdO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vICBDYWxjdWxhdGUgdGhlIG5ldyBzaWduYXR1cmVGcmFnbWVudCB3aXRoIHRoZSBmaXJzdCBidW5kbGUgZnJhZ21lbnRcbiAgICAgICAgICAgICAgICAgICAgdmFyIG5leHRTaWduZWRGcmFnbWVudCA9IFNpZ25pbmcuc2lnbmF0dXJlRnJhZ21lbnQobmV4dEJ1bmRsZUZyYWdtZW50LCBuZXh0RnJhZ21lbnQpO1xuXG4gICAgICAgICAgICAgICAgICAgIC8vICBDb252ZXJ0IHNpZ25hdHVyZSB0byB0cnl0ZXMgYW5kIGFkZCBuZXcgYnVuZGxlIGVudHJ5IGF0IGkgKyBqIHBvc2l0aW9uXG4gICAgICAgICAgICAgICAgICAgIC8vIEFzc2lnbiB0aGUgc2lnbmF0dXJlIGZyYWdtZW50XG4gICAgICAgICAgICAgICAgICAgIGJ1bmRsZS5idW5kbGVbaSArIGpdLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudCA9IENvbnZlcnRlci50cnl0ZXMobmV4dFNpZ25lZEZyYWdtZW50KTtcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiBjYWxsYmFjayhudWxsLCBidW5kbGUuYnVuZGxlKTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSBNdWx0aXNpZztcbiIsIi8vXG4vLyAgQ29udmVyc2lvbiBvZiBhc2NpaSBlbmNvZGVkIGJ5dGVzIHRvIHRyeXRlcy5cbi8vICBJbnB1dCBpcyBhIHN0cmluZyAoY2FuIGJlIHN0cmluZ2lmaWVkIEpTT04gb2JqZWN0KSwgcmV0dXJuIHZhbHVlIGlzIFRyeXRlc1xuLy9cbi8vICBIb3cgdGhlIGNvbnZlcnNpb24gd29ya3M6XG4vLyAgICAyIFRyeXRlcyA9PT0gMSBCeXRlXG4vLyAgICBUaGVyZSBhcmUgYSB0b3RhbCBvZiAyNyBkaWZmZXJlbnQgdHJ5dGUgdmFsdWVzOiA5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpcbi8vXG4vLyAgICAxLiBXZSBnZXQgdGhlIGRlY2ltYWwgdmFsdWUgb2YgYW4gaW5kaXZpZHVhbCBBU0NJSSBjaGFyYWN0ZXJcbi8vICAgIDIuIEZyb20gdGhlIGRlY2ltYWwgdmFsdWUsIHdlIHRoZW4gZGVyaXZlIHRoZSB0d28gdHJ5dGUgdmFsdWVzIGJ5IGJhc2ljYWxseSBjYWxjdWxhdGluZyB0aGUgdHJ5dGUgZXF1aXZhbGVudCAoZS5nLiAxMDAgPT09IDE5ICsgMyAqIDI3KVxuLy8gICAgICBhLiBUaGUgZmlyc3QgdHJ5dGUgdmFsdWUgaXMgdGhlIGRlY2ltYWwgdmFsdWUgbW9kdWxvIDI3ICgyNyB0cnl0ZXMpXG4vLyAgICAgIGIuIFRoZSBzZWNvbmQgdmFsdWUgaXMgdGhlIHJlbWFpbmRlciAoZGVjaW1hbCB2YWx1ZSAtIGZpcnN0IHZhbHVlKSwgZGl2aWRlZCBieSAyN1xuLy8gICAgMy4gVGhlIHR3byB2YWx1ZXMgcmV0dXJuZWQgZnJvbSBTdGVwIDIuIGFyZSB0aGVuIGlucHV0IGFzIGluZGljZXMgaW50byB0aGUgYXZhaWxhYmxlIHZhbHVlcyBsaXN0ICgnOUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaJykgdG8gZ2V0IHRoZSBjb3JyZWN0IHRyeXRlIHZhbHVlXG4vL1xuLy8gICBFWEFNUExFU1xuLy8gICAgICBMZXRzIHNheSB3ZSB3YW50IHRvIGNvbnZlcnQgdGhlIEFTQ0lJIGNoYXJhY3RlciBcIlpcIi5cbi8vICAgICAgICAxLiAnWicgaGFzIGEgZGVjaW1hbCB2YWx1ZSBvZiA5MC5cbi8vICAgICAgICAyLiA5MCBjYW4gYmUgcmVwcmVzZW50ZWQgYXMgOSArIDMgKiAyNy4gVG8gbWFrZSBpdCBzaW1wbGVyOlxuLy8gICAgICAgICAgIGEuIEZpcnN0IHZhbHVlOiA5MCBtb2R1bG8gMjcgaXMgOS4gVGhpcyBpcyBub3cgb3VyIGZpcnN0IHZhbHVlXG4vLyAgICAgICAgICAgYi4gU2Vjb25kIHZhbHVlOiAoOTAgLSA5KSAvIDI3IGlzIDMuIFRoaXMgaXMgb3VyIHNlY29uZCB2YWx1ZS5cbi8vICAgICAgICAzLiBPdXIgdHdvIHZhbHVlcyBhcmUgbm93IDkgYW5kIDMuIFRvIGdldCB0aGUgdHJ5dGUgdmFsdWUgbm93IHdlIHNpbXBseSBpbnNlcnQgaXQgYXMgaW5kaWNlcyBpbnRvICc5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVonXG4vLyAgICAgICAgICAgYS4gVGhlIGZpcnN0IHRyeXRlIHZhbHVlIGlzICc5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVonWzldID09PSBcIklcIlxuLy8gICAgICAgICAgIGIuIFRoZSBzZWNvbmQgdHJ5dGUgdmFsdWUgaXMgJzlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWidbM10gPT09IFwiQ1wiXG4vLyAgICAgICAgT3VyIHRyeXRlIHBhaXIgaXMgXCJJQ1wiXG4vL1xuLy8gICAgICBSRVNVTFQ6XG4vLyAgICAgICAgVGhlIEFTQ0lJIGNoYXIgXCJaXCIgaXMgcmVwcmVzZW50ZWQgYXMgXCJJQ1wiIGluIHRyeXRlcy5cbi8vXG5mdW5jdGlvbiB0b1RyeXRlcyhpbnB1dCkge1xuXG4gICAgLy8gSWYgaW5wdXQgaXMgbm90IGEgc3RyaW5nLCByZXR1cm4gbnVsbFxuICAgIGlmICggdHlwZW9mIGlucHV0ICE9PSAnc3RyaW5nJyApIHJldHVybiBudWxsXG5cbiAgICB2YXIgVFJZVEVfVkFMVUVTID0gXCI5QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpcIjtcbiAgICB2YXIgdHJ5dGVzID0gXCJcIjtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaW5wdXQubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgdmFyIGNoYXIgPSBpbnB1dFtpXTtcbiAgICAgICAgdmFyIGFzY2lpVmFsdWUgPSBjaGFyLmNoYXJDb2RlQXQoMCk7XG5cbiAgICAgICAgLy8gSWYgbm90IHJlY29nbml6YWJsZSBBU0NJSSBjaGFyYWN0ZXIsIHJldHVybiBudWxsXG4gICAgICAgIGlmIChhc2NpaVZhbHVlID4gMjU1KSB7XG4gICAgICAgICAgICAvL2FzY2lpVmFsdWUgPSAzMlxuICAgICAgICAgICAgcmV0dXJuIG51bGw7XG4gICAgICAgIH1cblxuICAgICAgICB2YXIgZmlyc3RWYWx1ZSA9IGFzY2lpVmFsdWUgJSAyNztcbiAgICAgICAgdmFyIHNlY29uZFZhbHVlID0gKGFzY2lpVmFsdWUgLSBmaXJzdFZhbHVlKSAvIDI3O1xuXG4gICAgICAgIHZhciB0cnl0ZXNWYWx1ZSA9IFRSWVRFX1ZBTFVFU1tmaXJzdFZhbHVlXSArIFRSWVRFX1ZBTFVFU1tzZWNvbmRWYWx1ZV07XG5cbiAgICAgICAgdHJ5dGVzICs9IHRyeXRlc1ZhbHVlO1xuICAgIH1cblxuICAgIHJldHVybiB0cnl0ZXM7XG59XG5cblxuLy9cbi8vICBUcnl0ZXMgdG8gYnl0ZXNcbi8vICBSZXZlcnNlIG9wZXJhdGlvbiBmcm9tIHRoZSBieXRlVG9Ucnl0ZXMgZnVuY3Rpb24gaW4gc2VuZC5qc1xuLy8gIDIgVHJ5dGVzID09IDEgQnl0ZVxuLy8gIFdlIGFzc3VtZSB0aGF0IHRoZSB0cnl0ZXMgYXJlIGEgSlNPTiBlbmNvZGVkIG9iamVjdCB0aHVzIGZvciBvdXIgZW5jb2Rpbmc6XG4vLyAgICBGaXJzdCBjaGFyYWN0ZXIgPSB7XG4vLyAgICBMYXN0IGNoYXJhY3RlciA9IH1cbi8vICAgIEV2ZXJ5dGhpbmcgYWZ0ZXIgdGhhdCBpcyA5J3MgcGFkZGluZ1xuLy9cbmZ1bmN0aW9uIGZyb21Ucnl0ZXMoaW5wdXRUcnl0ZXMpIHtcblxuICAgIC8vIElmIGlucHV0IGlzIG5vdCBhIHN0cmluZywgcmV0dXJuIG51bGxcbiAgICBpZiAoIHR5cGVvZiBpbnB1dFRyeXRlcyAhPT0gJ3N0cmluZycgKSByZXR1cm4gbnVsbFxuXG4gICAgLy8gSWYgaW5wdXQgbGVuZ3RoIGlzIG9kZCwgcmV0dXJuIG51bGxcbiAgICBpZiAoIGlucHV0VHJ5dGVzLmxlbmd0aCAlIDIgKSByZXR1cm4gbnVsbFxuXG4gICAgdmFyIFRSWVRFX1ZBTFVFUyA9IFwiOUFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaXCI7XG4gICAgdmFyIG91dHB1dFN0cmluZyA9IFwiXCI7XG5cbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGlucHV0VHJ5dGVzLmxlbmd0aDsgaSArPSAyKSB7XG4gICAgICAgIC8vIGdldCBhIHRyeXRlcyBwYWlyXG4gICAgICAgIHZhciB0cnl0ZXMgPSBpbnB1dFRyeXRlc1tpXSArIGlucHV0VHJ5dGVzW2kgKyAxXTtcblxuICAgICAgICB2YXIgZmlyc3RWYWx1ZSA9IFRSWVRFX1ZBTFVFUy5pbmRleE9mKHRyeXRlc1swXSk7XG4gICAgICAgIHZhciBzZWNvbmRWYWx1ZSA9IFRSWVRFX1ZBTFVFUy5pbmRleE9mKHRyeXRlc1sxXSk7XG5cbiAgICAgICAgdmFyIGRlY2ltYWxWYWx1ZSA9IGZpcnN0VmFsdWUgKyBzZWNvbmRWYWx1ZSAqIDI3O1xuXG4gICAgICAgIHZhciBjaGFyYWN0ZXIgPSBTdHJpbmcuZnJvbUNoYXJDb2RlKGRlY2ltYWxWYWx1ZSk7XG5cbiAgICAgICAgb3V0cHV0U3RyaW5nICs9IGNoYXJhY3RlcjtcbiAgICB9XG5cbiAgICByZXR1cm4gb3V0cHV0U3RyaW5nO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgICB0b1RyeXRlczogdG9Ucnl0ZXMsXG4gICAgZnJvbVRyeXRlczogZnJvbVRyeXRlc1xufVxuIiwidmFyIGFzY2lpID0gcmVxdWlyZShcIi4vYXNjaWlUb1RyeXRlc1wiKTtcbnZhciBpbnB1dFZhbGlkYXRvciA9IHJlcXVpcmUoXCIuL2lucHV0VmFsaWRhdG9yXCIpO1xuXG4vKipcbiogICBleHRyYWN0SnNvbiB0YWtlcyBhIGJ1bmRsZSBhcyBpbnB1dCBhbmQgZnJvbSB0aGUgc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50cyBleHRyYWN0cyB0aGUgY29ycmVjdCBKU09OXG4qICAgZGF0YSB3aGljaCB3YXMgZW5jb2RlZCBhbmQgc2VudCB3aXRoIHRoZSB0cmFuc2FjdGlvbi5cbipcbiogICBAbWV0aG9kIGV4dHJhY3RKc29uXG4qICAgQHBhcmFtIHthcnJheX0gYnVuZGxlXG4qICAgQHJldHVybnMge09iamVjdH1cbioqL1xuZnVuY3Rpb24gZXh0cmFjdEpzb24oYnVuZGxlKSB7XG5cbiAgICAvLyBpZiB3cm9uZyBpbnB1dCByZXR1cm4gbnVsbFxuICAgIGlmICggIWlucHV0VmFsaWRhdG9yLmlzQXJyYXkoYnVuZGxlKSB8fCBidW5kbGVbMF0gPT09IHVuZGVmaW5lZCApIHJldHVybiBudWxsO1xuXG5cbiAgICAvLyBTYW5pdHkgY2hlY2s6IGlmIHRoZSBmaXJzdCB0cnl0ZSBwYWlyIGlzIG5vdCBvcGVuaW5nIGJyYWNrZXQsIGl0J3Mgbm90IGEgbWVzc2FnZVxuICAgIHZhciBmaXJzdFRyeXRlUGFpciA9IGJ1bmRsZVswXS5zaWduYXR1cmVNZXNzYWdlRnJhZ21lbnRbMF0gKyBidW5kbGVbMF0uc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50WzFdO1xuXG4gICAgaWYgKGZpcnN0VHJ5dGVQYWlyICE9PSBcIk9EXCIpIHJldHVybiBudWxsO1xuXG4gICAgdmFyIGluZGV4ID0gMDtcbiAgICB2YXIgbm90RW5kZWQgPSB0cnVlO1xuICAgIHZhciB0cnl0ZXNDaHVuayA9ICcnO1xuICAgIHZhciB0cnl0ZXNDaGVja2VkID0gMDtcbiAgICB2YXIgcHJlbGltaW5hcnlTdG9wID0gZmFsc2U7XG4gICAgdmFyIGZpbmFsSnNvbiA9ICcnO1xuXG4gICAgd2hpbGUgKGluZGV4IDwgYnVuZGxlLmxlbmd0aCAmJiBub3RFbmRlZCkge1xuXG4gICAgICAgIHZhciBtZXNzYWdlQ2h1bmsgPSBidW5kbGVbaW5kZXhdLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudDtcblxuICAgICAgICAvLyBXZSBpdGVyYXRlIG92ZXIgdGhlIG1lc3NhZ2UgY2h1bmssIHJlYWRpbmcgOSB0cnl0ZXMgYXQgYSB0aW1lXG4gICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgbWVzc2FnZUNodW5rLmxlbmd0aDsgaSArPSA5KSB7XG5cbiAgICAgICAgICAgIC8vIGdldCA5IHRyeXRlc1xuICAgICAgICAgICAgdmFyIHRyeXRlcyA9IG1lc3NhZ2VDaHVuay5zbGljZShpLCBpICsgOSk7XG4gICAgICAgICAgICB0cnl0ZXNDaHVuayArPSB0cnl0ZXM7XG5cbiAgICAgICAgICAgIC8vIEdldCB0aGUgdXBwZXIgbGltaXQgb2YgdGhlIHR5dGVzIHRoYXQgbmVlZCB0byBiZSBjaGVja2VkXG4gICAgICAgICAgICAvLyBiZWNhdXNlIHdlIG9ubHkgY2hlY2sgMiB0cnl0ZXMgYXQgYSB0aW1lLCB0aGVyZSBpcyBzb21ldGltZXMgYSBsZWZ0b3ZlclxuICAgICAgICAgICAgdmFyIHVwcGVyTGltaXQgPSB0cnl0ZXNDaHVuay5sZW5ndGggLSB0cnl0ZXNDaHVuay5sZW5ndGggJSAyO1xuXG4gICAgICAgICAgICB2YXIgdHJ5dGVzVG9DaGVjayA9IHRyeXRlc0NodW5rLnNsaWNlKHRyeXRlc0NoZWNrZWQsIHVwcGVyTGltaXQpO1xuXG4gICAgICAgICAgICAvLyBXZSByZWFkIDIgdHJ5dGVzIGF0IGEgdGltZSBhbmQgY2hlY2sgaWYgaXQgZXF1YWxzIHRoZSBjbG9zaW5nIGJyYWNrZXQgY2hhcmFjdGVyXG4gICAgICAgICAgICBmb3IgKHZhciBqID0gMDsgaiA8IHRyeXRlc1RvQ2hlY2subGVuZ3RoOyBqICs9IDIpIHtcblxuICAgICAgICAgICAgICAgIHZhciB0cnl0ZVBhaXIgPSB0cnl0ZXNUb0NoZWNrW2pdICsgdHJ5dGVzVG9DaGVja1tqICsgMV07XG5cbiAgICAgICAgICAgICAgICAvLyBJZiBjbG9zaW5nIGJyYWNrZXQgY2hhciB3YXMgZm91bmQsIGFuZCB0aGVyZSBhcmUgb25seSB0cmFpbGluZyA5J3NcbiAgICAgICAgICAgICAgICAvLyB3ZSBxdWl0IGFuZCByZW1vdmUgdGhlIDkncyBmcm9tIHRoZSB0cnl0ZXNDaHVuay5cbiAgICAgICAgICAgICAgICBpZiAoIHByZWxpbWluYXJ5U3RvcCAmJiB0cnl0ZVBhaXIgPT09ICc5OScgKSB7XG5cbiAgICAgICAgICAgICAgICAgICAgbm90RW5kZWQgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICAgICAgLy8gVE9ETzogUmVtb3ZlIHRoZSB0cmFpbGluZyA5J3MgZnJvbSB0cnl0ZXNDaHVua1xuICAgICAgICAgICAgICAgICAgICAvL3ZhciBjbG9zaW5nQnJhY2tldCA9IHRyeXRlc1RvQ2hlY2suaW5kZXhPZignUUQnKSArIDE7XG5cbiAgICAgICAgICAgICAgICAgICAgLy90cnl0ZXNDaHVuayA9IHRyeXRlc0NodW5rLnNsaWNlKCAwLCAoIHRyeXRlc0NodW5rLmxlbmd0aCAtIHRyeXRlc1RvQ2hlY2subGVuZ3RoICkgKyAoIGNsb3NpbmdCcmFja2V0ICUgMiA9PT0gMCA/IGNsb3NpbmdCcmFja2V0IDogY2xvc2luZ0JyYWNrZXQgKyAxICkgKTtcblxuICAgICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgICB9XG5cbiAgICAgICAgICAgICAgICBmaW5hbEpzb24gKz0gYXNjaWkuZnJvbVRyeXRlcyh0cnl0ZVBhaXIpO1xuXG4gICAgICAgICAgICAgICAgLy8gSWYgdHJ5dGUgcGFpciBlcXVhbHMgY2xvc2luZyBicmFja2V0IGNoYXIsIHdlIHNldCBhIHByZWxpbWluYXJ5IHN0b3BcbiAgICAgICAgICAgICAgICAvLyB0aGUgcHJlbGltaW5hcnlTdG9wIGlzIHVzZWZ1bCB3aGVuIHdlIGhhdmUgYSBuZXN0ZWQgSlNPTiBvYmplY3RcbiAgICAgICAgICAgICAgICBpZiAodHJ5dGVQYWlyID09PSBcIlFEXCIpIHtcbiAgICAgICAgICAgICAgICAgICAgcHJlbGltaW5hcnlTdG9wID0gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG5cbiAgICAgICAgICAgIGlmICghbm90RW5kZWQpXG4gICAgICAgICAgICAgICAgYnJlYWs7XG5cbiAgICAgICAgICAgIHRyeXRlc0NoZWNrZWQgKz0gdHJ5dGVzVG9DaGVjay5sZW5ndGg7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBJZiB3ZSBoYXZlIG5vdCByZWFjaGVkIHRoZSBlbmQgb2YgdGhlIG1lc3NhZ2UgeWV0LCB3ZSBjb250aW51ZSB3aXRoIHRoZSBuZXh0XG4gICAgICAgIC8vIHRyYW5zYWN0aW9uIGluIHRoZSBidW5kbGVcbiAgICAgICAgaW5kZXggKz0gMTtcblxuICAgIH1cblxuICAgIC8vIElmIHdlIGRpZCBub3QgZmluZCBhbnkgSlNPTiwgcmV0dXJuIG51bGxcbiAgICBpZiAobm90RW5kZWQpIHtcblxuICAgICAgICByZXR1cm4gbnVsbDtcblxuICAgIH0gZWxzZSB7XG5cbiAgICAgICAgcmV0dXJuIGZpbmFsSnNvbjtcblxuICAgIH1cbn1cblxubW9kdWxlLmV4cG9ydHMgPSBleHRyYWN0SnNvbjtcbiIsIi8qKlxuKiAgIGNoZWNrcyBpZiBpbnB1dCBpcyBjb3JyZWN0IGFkZHJlc3NcbipcbiogICBAbWV0aG9kIGlzQWRkcmVzc1xuKiAgIEBwYXJhbSB7c3RyaW5nfSBhZGRyZXNzXG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc0FkZHJlc3MgPSBmdW5jdGlvbihhZGRyZXNzKSB7XG4gICAgLy8gVE9ETzogSW4gdGhlIGZ1dHVyZSBjaGVjayBjaGVja3N1bVxuXG4gICAgLy8gQ2hlY2sgaWYgYWRkcmVzcyB3aXRoIGNoZWNrc3VtXG4gICAgaWYgKGFkZHJlc3MubGVuZ3RoID09PSA5MCkge1xuXG4gICAgICAgIGlmICghaXNUcnl0ZXMoYWRkcmVzcywgOTApKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICB9IGVsc2Uge1xuXG4gICAgICAgIGlmICghaXNUcnl0ZXMoYWRkcmVzcywgODEpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbn1cblxuLyoqXG4qICAgY2hlY2tzIGlmIGlucHV0IGlzIGNvcnJlY3QgdHJ5dGVzIGNvbnNpc3Rpbmcgb2YgQS1aOVxuKiAgIG9wdGlvbmFsbHkgdmFsaWRhdGUgbGVuZ3RoXG4qXG4qICAgQG1ldGhvZCBpc1RyeXRlc1xuKiAgIEBwYXJhbSB7c3RyaW5nfSB0cnl0ZXNcbiogICBAcGFyYW0ge2ludGVnZXJ9IGxlbmd0aCBvcHRpb25hbFxuKiAgIEByZXR1cm5zIHtib29sZWFufVxuKiovXG52YXIgaXNUcnl0ZXMgPSBmdW5jdGlvbih0cnl0ZXMsIGxlbmd0aCkge1xuXG4gICAgLy8gSWYgbm8gbGVuZ3RoIHNwZWNpZmllZCwganVzdCB2YWxpZGF0ZSB0aGUgdHJ5dGVzXG4gICAgaWYgKCFsZW5ndGgpIGxlbmd0aCA9IFwiMCxcIlxuXG4gICAgdmFyIHJlZ2V4VHJ5dGVzID0gbmV3IFJlZ0V4cChcIl5bOUEtWl17XCIgKyBsZW5ndGggK1wifSRcIik7XG4gICAgcmV0dXJuIHJlZ2V4VHJ5dGVzLnRlc3QodHJ5dGVzKSAmJiBpc1N0cmluZyh0cnl0ZXMpO1xufVxuXG4vKipcbiogICBjaGVja3MgaWYgaW5wdXQgaXMgY29ycmVjdCB0cnl0ZXMgY29uc2lzdGluZyBvZiBBLVo5XG4qICAgb3B0aW9uYWxseSB2YWxpZGF0ZSBsZW5ndGhcbipcbiogICBAbWV0aG9kIGlzTmluZXNUcnl0ZXNcbiogICBAcGFyYW0ge3N0cmluZ30gdHJ5dGVzXG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc05pbmVzVHJ5dGVzID0gZnVuY3Rpb24odHJ5dGVzKSB7XG5cbiAgICByZXR1cm4gL15bOV0rJC8udGVzdCh0cnl0ZXMpICYmIGlzU3RyaW5nKHRyeXRlcyk7XG59XG5cbi8qKlxuKiAgIGNoZWNrcyBpZiBpbnRlZ2VyIHZhbHVlXG4qXG4qICAgQG1ldGhvZCBpc1ZhbHVlXG4qICAgQHBhcmFtIHtzdHJpbmd9IHZhbHVlXG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc1ZhbHVlID0gZnVuY3Rpb24odmFsdWUpIHtcblxuICAgIC8vIGNoZWNrIGlmIGNvcnJlY3QgbnVtYmVyXG4gICAgcmV0dXJuIE51bWJlci5pc0ludGVnZXIodmFsdWUpXG59XG5cbi8qKlxuKiAgIGNoZWNrcyB3aGV0aGVyIGlucHV0IGlzIGEgdmFsdWUgb3Igbm90LiBDYW4gYmUgYSBzdHJpbmcsIGZsb2F0IG9yIGludGVnZXJcbipcbiogICBAbWV0aG9kIGlzTnVtXG4qICAgQHBhcmFtIHtpbnR9XG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc051bSA9IGZ1bmN0aW9uKGlucHV0KSB7XG5cbiAgICByZXR1cm4gL14oXFxkK1xcLj9cXGR7MCwxNX18XFwuXFxkezAsMTV9KSQvLnRlc3QoaW5wdXQpO1xufVxuXG4vKipcbiogICBjaGVja3MgaWYgaW5wdXQgaXMgY29ycmVjdCBoYXNoXG4qXG4qICAgQG1ldGhvZCBpc0hhc2hcbiogICBAcGFyYW0ge3N0cmluZ30gaGFzaFxuKiAgIEByZXR1cm5zIHtib29sZWFufVxuKiovXG52YXIgaXNIYXNoID0gZnVuY3Rpb24oaGFzaCkge1xuXG4gICAgLy8gQ2hlY2sgaWYgdmFsaWQsIDgxIHRyeXRlc1xuICAgIGlmICghaXNUcnl0ZXMoaGFzaCwgODEpKSB7XG5cbiAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xufVxuXG4vKipcbiogICBjaGVja3Mgd2hldGhlciBpbnB1dCBpcyBhIHN0cmluZyBvciBub3RcbipcbiogICBAbWV0aG9kIGlzU3RyaW5nXG4qICAgQHBhcmFtIHtzdHJpbmd9XG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc1N0cmluZyA9IGZ1bmN0aW9uKHN0cmluZykge1xuXG4gICAgcmV0dXJuIHR5cGVvZiBzdHJpbmcgPT09ICdzdHJpbmcnO1xufVxuXG5cbi8qKlxuKiAgIGNoZWNrcyB3aGV0aGVyIGlucHV0IGlzIGFuIGFycmF5IG9yIG5vdFxuKlxuKiAgIEBtZXRob2QgaXNBcnJheVxuKiAgIEBwYXJhbSB7b2JqZWN0fVxuKiAgIEByZXR1cm5zIHtib29sZWFufVxuKiovXG52YXIgaXNBcnJheSA9IGZ1bmN0aW9uKGFycmF5KSB7XG5cbiAgICByZXR1cm4gYXJyYXkgaW5zdGFuY2VvZiBBcnJheTtcbn1cblxuXG4vKipcbiogICBjaGVja3Mgd2hldGhlciBpbnB1dCBpcyBvYmplY3Qgb3Igbm90XG4qXG4qICAgQG1ldGhvZCBpc09iamVjdFxuKiAgIEBwYXJhbSB7b2JqZWN0fVxuKiAgIEByZXR1cm5zIHtib29sZWFufVxuKiovXG52YXIgaXNPYmplY3QgPSBmdW5jdGlvbihvYmplY3QpIHtcblxuICAgIHJldHVybiB0eXBlb2Ygb2JqZWN0ID09PSAnb2JqZWN0Jztcbn1cblxuXG5cbi8qKlxuKiAgIGNoZWNrcyBpZiBpbnB1dCBpcyBjb3JyZWN0IGhhc2hcbipcbiogICBAbWV0aG9kIGlzVHJhbnNmZXJzQXJyYXlcbiogICBAcGFyYW0ge2FycmF5fSBoYXNoXG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc1RyYW5zZmVyc0FycmF5ID0gZnVuY3Rpb24odHJhbnNmZXJzQXJyYXkpIHtcblxuICAgIGlmICghaXNBcnJheSh0cmFuc2ZlcnNBcnJheSkpIHJldHVybiBmYWxzZTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdHJhbnNmZXJzQXJyYXkubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICB2YXIgdHJhbnNmZXIgPSB0cmFuc2ZlcnNBcnJheVtpXTtcblxuICAgICAgICAvLyBDaGVjayBpZiB2YWxpZCBhZGRyZXNzXG4gICAgICAgIHZhciBhZGRyZXNzID0gdHJhbnNmZXIuYWRkcmVzcztcbiAgICAgICAgaWYgKCFpc0FkZHJlc3MoYWRkcmVzcykpIHtcbiAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgfVxuXG4gICAgICAgIC8vIFZhbGlkaXR5IGNoZWNrIGZvciB2YWx1ZVxuICAgICAgICB2YXIgdmFsdWUgPSB0cmFuc2Zlci52YWx1ZTtcbiAgICAgICAgaWYgKCFpc1ZhbHVlKHZhbHVlKSkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG5cbiAgICAgICAgLy8gQ2hlY2sgaWYgbWVzc2FnZSBpcyBjb3JyZWN0IHRyeXRlcyBvZiBhbnkgbGVuZ3RoXG4gICAgICAgIHZhciBtZXNzYWdlID0gdHJhbnNmZXIubWVzc2FnZTtcbiAgICAgICAgaWYgKCFpc1RyeXRlcyhtZXNzYWdlLCBcIjAsXCIpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICAvLyBDaGVjayBpZiB0YWcgaXMgY29ycmVjdCB0cnl0ZXMgb2YgezAsMjd9IHRyeXRlc1xuICAgICAgICB2YXIgdGFnID0gdHJhbnNmZXIudGFnIHx8IHRyYW5zZmVyLm9ic29sZXRlVGFnO1xuICAgICAgICBpZiAoIWlzVHJ5dGVzKHRhZywgXCIwLDI3XCIpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xufVxuXG4vKipcbiogICBjaGVja3MgaWYgaW5wdXQgaXMgbGlzdCBvZiBjb3JyZWN0IHRyeXRlc1xuKlxuKiAgIEBtZXRob2QgaXNBcnJheU9mSGFzaGVzXG4qICAgQHBhcmFtIHtsaXN0fSBoYXNoZXNBcnJheVxuKiAgIEByZXR1cm5zIHtib29sZWFufVxuKiovXG52YXIgaXNBcnJheU9mSGFzaGVzID0gZnVuY3Rpb24oaGFzaGVzQXJyYXkpIHtcblxuICAgIGlmICghaXNBcnJheShoYXNoZXNBcnJheSkpIHJldHVybiBmYWxzZTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaGFzaGVzQXJyYXkubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICB2YXIgaGFzaCA9IGhhc2hlc0FycmF5W2ldO1xuXG4gICAgICAgIC8vIENoZWNrIGlmIGFkZHJlc3Mgd2l0aCBjaGVja3N1bVxuICAgICAgICBpZiAoaGFzaC5sZW5ndGggPT09IDkwKSB7XG5cbiAgICAgICAgICAgIGlmICghaXNUcnl0ZXMoaGFzaCwgOTApKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICB9IGVsc2Uge1xuXG4gICAgICAgICAgICBpZiAoIWlzVHJ5dGVzKGhhc2gsIDgxKSkge1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH1cblxuICAgIHJldHVybiB0cnVlO1xufVxuXG4vKipcbiogICBjaGVja3MgaWYgaW5wdXQgaXMgbGlzdCBvZiBjb3JyZWN0IHRyeXRlc1xuKlxuKiAgIEBtZXRob2QgaXNBcnJheU9mVHJ5dGVzXG4qICAgQHBhcmFtIHtsaXN0fSB0cnl0ZXNBcnJheVxuKiAgIEByZXR1cm5zIHtib29sZWFufVxuKiovXG52YXIgaXNBcnJheU9mVHJ5dGVzID0gZnVuY3Rpb24odHJ5dGVzQXJyYXkpIHtcblxuICAgIGlmICghaXNBcnJheSh0cnl0ZXNBcnJheSkpIHJldHVybiBmYWxzZTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgdHJ5dGVzQXJyYXkubGVuZ3RoOyBpKyspIHtcblxuICAgICAgICB2YXIgdHJ5dGVWYWx1ZSA9IHRyeXRlc0FycmF5W2ldO1xuXG4gICAgICAgIC8vIENoZWNrIGlmIGNvcnJlY3QgMjY3MyB0cnl0ZXNcbiAgICAgICAgaWYgKCFpc1RyeXRlcyh0cnl0ZVZhbHVlLCAyNjczKSkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG59XG5cbi8qKlxuKiAgIGNoZWNrcyBpZiBhdHRhY2hlZCB0cnl0ZXMgaWYgbGFzdCAyNDEgdHJ5dGVzIGFyZSBub24temVyb1xuKlxuKiAgIEBtZXRob2QgaXNBcnJheU9mQXR0YWNoZWRUcnl0ZXNcbiogICBAcGFyYW0ge2FycmF5fSB0cnl0ZXNBcnJheVxuKiAgIEByZXR1cm5zIHtib29sZWFufVxuKiovXG52YXIgaXNBcnJheU9mQXR0YWNoZWRUcnl0ZXMgPSBmdW5jdGlvbih0cnl0ZXNBcnJheSkge1xuXG4gICAgaWYgKCFpc0FycmF5KHRyeXRlc0FycmF5KSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCB0cnl0ZXNBcnJheS5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIHZhciB0cnl0ZVZhbHVlID0gdHJ5dGVzQXJyYXlbaV07XG5cbiAgICAgICAgLy8gQ2hlY2sgaWYgY29ycmVjdCAyNjczIHRyeXRlc1xuICAgICAgICBpZiAoIWlzVHJ5dGVzKHRyeXRlVmFsdWUsIDI2NzMpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICB2YXIgbGFzdFRyeXRlcyA9IHRyeXRlVmFsdWUuc2xpY2UoMjY3MyAtICgzICogODEpKTtcblxuICAgICAgICBpZiAoL15bOV0rJC8udGVzdChsYXN0VHJ5dGVzKSkge1xuICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICB9XG4gICAgfVxuXG4gICAgcmV0dXJuIHRydWU7XG59XG5cbi8qKlxuKiAgIGNoZWNrcyBpZiBjb3JyZWN0IGJ1bmRsZSB3aXRoIHRyYW5zYWN0aW9uIG9iamVjdFxuKlxuKiAgIEBtZXRob2QgaXNBcnJheU9mVHhPYmplY3RzXG4qICAgQHBhcmFtIHthcnJheX0gYnVuZGxlXG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc0FycmF5T2ZUeE9iamVjdHMgPSBmdW5jdGlvbihidW5kbGUpIHtcblxuICAgIGlmICghaXNBcnJheShidW5kbGUpIHx8IGJ1bmRsZS5sZW5ndGggPT09IDApIHJldHVybiBmYWxzZTtcblxuICAgIHZhciB2YWxpZEFycmF5ID0gdHJ1ZTtcblxuICAgIGJ1bmRsZS5mb3JFYWNoKGZ1bmN0aW9uKHR4T2JqZWN0KSB7XG5cbiAgICAgICAgdmFyIGtleXNUb1ZhbGlkYXRlID0gW1xuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIGtleTogJ2hhc2gnLFxuICAgICAgICAgICAgICAgIHZhbGlkYXRvcjogaXNIYXNoLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICdzaWduYXR1cmVNZXNzYWdlRnJhZ21lbnQnLFxuICAgICAgICAgICAgICAgIHZhbGlkYXRvcjogaXNUcnl0ZXMsXG4gICAgICAgICAgICAgICAgYXJnczogMjE4N1xuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ2FkZHJlc3MnLFxuICAgICAgICAgICAgICAgIHZhbGlkYXRvcjogaXNIYXNoLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICd2YWx1ZScsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1ZhbHVlLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICdvYnNvbGV0ZVRhZycsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1RyeXRlcyxcbiAgICAgICAgICAgICAgICBhcmdzOiAyN1xuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ3RpbWVzdGFtcCcsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1ZhbHVlLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICdjdXJyZW50SW5kZXgnLFxuICAgICAgICAgICAgICAgIHZhbGlkYXRvcjogaXNWYWx1ZSxcbiAgICAgICAgICAgICAgICBhcmdzOiBudWxsXG4gICAgICAgICAgICB9LHtcbiAgICAgICAgICAgICAgICBrZXk6ICdsYXN0SW5kZXgnLFxuICAgICAgICAgICAgICAgIHZhbGlkYXRvcjogaXNWYWx1ZSxcbiAgICAgICAgICAgICAgICBhcmdzOiBudWxsXG4gICAgICAgICAgICB9LCB7XG4gICAgICAgICAgICAgICAga2V5OiAnYnVuZGxlJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzSGFzaCxcbiAgICAgICAgICAgICAgICBhcmdzOiBudWxsXG4gICAgICAgICAgICB9LCB7XG4gICAgICAgICAgICAgICAga2V5OiAndHJ1bmtUcmFuc2FjdGlvbicsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc0hhc2gsXG4gICAgICAgICAgICAgICAgYXJnczogbnVsbFxuICAgICAgICAgICAgfSwge1xuICAgICAgICAgICAgICAgIGtleTogJ2JyYW5jaFRyYW5zYWN0aW9uJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzSGFzaCxcbiAgICAgICAgICAgICAgICBhcmdzOiBudWxsXG4gICAgICAgICAgICB9LCB7XG4gICAgICAgICAgICAgICAga2V5OiAndGFnJyxcbiAgICAgICAgICAgICAgICB2YWxpZGF0b3I6IGlzVHJ5dGVzLFxuICAgICAgICAgICAgICAgIGFyZ3M6IDI3XG4gICAgICAgICAgICB9LCB7XG4gICAgICAgICAgICAgICAga2V5OiAnYXR0YWNobWVudFRpbWVzdGFtcCcsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1ZhbHVlLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICdhdHRhY2htZW50VGltZXN0YW1wTG93ZXJCb3VuZCcsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1ZhbHVlLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICdhdHRhY2htZW50VGltZXN0YW1wVXBwZXJCb3VuZCcsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1ZhbHVlLFxuICAgICAgICAgICAgICAgIGFyZ3M6IG51bGxcbiAgICAgICAgICAgIH0sIHtcbiAgICAgICAgICAgICAgICBrZXk6ICdub25jZScsXG4gICAgICAgICAgICAgICAgdmFsaWRhdG9yOiBpc1RyeXRlcyxcbiAgICAgICAgICAgICAgICBhcmdzOiAyN1xuICAgICAgICAgICAgfVxuICAgICAgICBdXG5cbiAgICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBrZXlzVG9WYWxpZGF0ZS5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgICAgICB2YXIga2V5ID0ga2V5c1RvVmFsaWRhdGVbaV0ua2V5O1xuICAgICAgICAgICAgdmFyIHZhbGlkYXRvciA9IGtleXNUb1ZhbGlkYXRlW2ldLnZhbGlkYXRvcjtcbiAgICAgICAgICAgIHZhciBhcmdzID0ga2V5c1RvVmFsaWRhdGVbaV0uYXJnc1xuXG4gICAgICAgICAgICAvLyBJZiBpbnB1dCBkb2VzIG5vdCBoYXZlIGtleUluZGV4IGFuZCBhZGRyZXNzLCByZXR1cm4gZmFsc2VcbiAgICAgICAgICAgIGlmICghdHhPYmplY3QuaGFzT3duUHJvcGVydHkoa2V5KSkge1xuICAgICAgICAgICAgICAgIHZhbGlkQXJyYXkgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgLy8gSWYgaW5wdXQgdmFsaWRhdG9yIGZ1bmN0aW9uIGRvZXMgbm90IHJldHVybiB0cnVlLCBleGl0XG4gICAgICAgICAgICBpZiAoIXZhbGlkYXRvcih0eE9iamVjdFtrZXldLCBhcmdzKSkge1xuICAgICAgICAgICAgICAgIHZhbGlkQXJyYXkgPSBmYWxzZTtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgIH0pXG5cbiAgICByZXR1cm4gdmFsaWRBcnJheTtcbn1cblxuLyoqXG4qICAgY2hlY2tzIGlmIGNvcnJlY3QgaW5wdXRzIGxpc3RcbipcbiogICBAbWV0aG9kIGlzSW5wdXRzXG4qICAgQHBhcmFtIHthcnJheX0gaW5wdXRzXG4qICAgQHJldHVybnMge2Jvb2xlYW59XG4qKi9cbnZhciBpc0lucHV0cyA9IGZ1bmN0aW9uKGlucHV0cykge1xuXG4gICAgaWYgKCFpc0FycmF5KGlucHV0cykpIHJldHVybiBmYWxzZTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgaW5wdXRzLmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgdmFyIGlucHV0ID0gaW5wdXRzW2ldO1xuXG4gICAgICAgIC8vIElmIGlucHV0IGRvZXMgbm90IGhhdmUga2V5SW5kZXggYW5kIGFkZHJlc3MsIHJldHVybiBmYWxzZVxuICAgICAgICBpZiAoIWlucHV0Lmhhc093blByb3BlcnR5KCdzZWN1cml0eScpIHx8ICFpbnB1dC5oYXNPd25Qcm9wZXJ0eSgna2V5SW5kZXgnKSB8fCAhaW5wdXQuaGFzT3duUHJvcGVydHkoJ2FkZHJlc3MnKSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIGlmICghaXNBZGRyZXNzKGlucHV0LmFkZHJlc3MpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWlzVmFsdWUoaW5wdXQuc2VjdXJpdHkpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cblxuICAgICAgICBpZiAoIWlzVmFsdWUoaW5wdXQua2V5SW5kZXgpKSB7XG4gICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgIH1cbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbn1cblxuLyoqXG4qICAgQ2hlY2tzIHRoYXQgYSBnaXZlbiB1cmkgaXMgdmFsaWRcbipcbiogICBWYWxpZCBFeGFtcGxlczpcbiogICB1ZHA6Ly9bMjAwMTpkYjg6YTBiOjEyZjA6OjFdOjE0MjY1XG4qICAgdWRwOi8vWzIwMDE6ZGI4OmEwYjoxMmYwOjoxXVxuKiAgIHVkcDovLzguOC44Ljg6MTQyNjVcbiogICB1ZHA6Ly9kb21haW4uY29tXG4qICAgdWRwOi8vZG9tYWluMi5jb206MTQyNjVcbipcbiogICBAbWV0aG9kIGlzVXJpXG4qICAgQHBhcmFtIHtzdHJpbmd9IG5vZGVcbiogICBAcmV0dXJucyB7Ym9vbH0gdmFsaWRcbioqL1xudmFyIGlzVXJpID0gZnVuY3Rpb24obm9kZSkge1xuXG4gICAgdmFyIGdldEluc2lkZSA9IC9eKHVkcHx0Y3ApOlxcL1xcLyhbXFxbXVteXFxdXFwuXSpbXFxdXXxbXlxcW1xcXTpdKilbOl17MCwxfShbMC05XXsxLH0kfCQpL2k7XG5cbiAgICB2YXIgc3RyaXBCcmFja2V0cyA9IC9bXFxbXXswLDF9KFteXFxbXFxdXSopW1xcXV17MCwxfS87XG5cbiAgICB2YXIgdXJpVGVzdCA9IC8oKF5cXHMqKCgoWzAtOV18WzEtOV1bMC05XXwxWzAtOV17Mn18MlswLTRdWzAtOV18MjVbMC01XSlcXC4pezN9KFswLTldfFsxLTldWzAtOV18MVswLTldezJ9fDJbMC00XVswLTldfDI1WzAtNV0pKVxccyokKXwoXlxccyooKChbMC05QS1GYS1mXXsxLDR9Oil7N30oWzAtOUEtRmEtZl17MSw0fXw6KSl8KChbMC05QS1GYS1mXXsxLDR9Oil7Nn0oOlswLTlBLUZhLWZdezEsNH18KCgyNVswLTVdfDJbMC00XVxcZHwxXFxkXFxkfFsxLTldP1xcZCkoXFwuKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKSl7M30pfDopKXwoKFswLTlBLUZhLWZdezEsNH06KXs1fSgoKDpbMC05QS1GYS1mXXsxLDR9KXsxLDJ9KXw6KCgyNVswLTVdfDJbMC00XVxcZHwxXFxkXFxkfFsxLTldP1xcZCkoXFwuKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKSl7M30pfDopKXwoKFswLTlBLUZhLWZdezEsNH06KXs0fSgoKDpbMC05QS1GYS1mXXsxLDR9KXsxLDN9KXwoKDpbMC05QS1GYS1mXXsxLDR9KT86KCgyNVswLTVdfDJbMC00XVxcZHwxXFxkXFxkfFsxLTldP1xcZCkoXFwuKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKSl7M30pKXw6KSl8KChbMC05QS1GYS1mXXsxLDR9Oil7M30oKCg6WzAtOUEtRmEtZl17MSw0fSl7MSw0fSl8KCg6WzAtOUEtRmEtZl17MSw0fSl7MCwyfTooKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKShcXC4oMjVbMC01XXwyWzAtNF1cXGR8MVxcZFxcZHxbMS05XT9cXGQpKXszfSkpfDopKXwoKFswLTlBLUZhLWZdezEsNH06KXsyfSgoKDpbMC05QS1GYS1mXXsxLDR9KXsxLDV9KXwoKDpbMC05QS1GYS1mXXsxLDR9KXswLDN9OigoMjVbMC01XXwyWzAtNF1cXGR8MVxcZFxcZHxbMS05XT9cXGQpKFxcLigyNVswLTVdfDJbMC00XVxcZHwxXFxkXFxkfFsxLTldP1xcZCkpezN9KSl8OikpfCgoWzAtOUEtRmEtZl17MSw0fTopezF9KCgoOlswLTlBLUZhLWZdezEsNH0pezEsNn0pfCgoOlswLTlBLUZhLWZdezEsNH0pezAsNH06KCgyNVswLTVdfDJbMC00XVxcZHwxXFxkXFxkfFsxLTldP1xcZCkoXFwuKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKSl7M30pKXw6KSl8KDooKCg6WzAtOUEtRmEtZl17MSw0fSl7MSw3fSl8KCg6WzAtOUEtRmEtZl17MSw0fSl7MCw1fTooKDI1WzAtNV18MlswLTRdXFxkfDFcXGRcXGR8WzEtOV0/XFxkKShcXC4oMjVbMC01XXwyWzAtNF1cXGR8MVxcZFxcZHxbMS05XT9cXGQpKXszfSkpfDopKSkoJS4rKT9cXHMqJCkpfCheXFxzKigoPz0uezEsMjU1fSQpKD89LipbQS1aYS16XS4qKVswLTlBLVphLXpdKD86KD86WzAtOUEtWmEtel18XFxiLSl7MCw2MX1bMC05QS1aYS16XSk/KD86XFwuWzAtOUEtWmEtel0oPzooPzpbMC05QS1aYS16XXxcXGItKXswLDYxfVswLTlBLVphLXpdKT8pKilcXHMqJCkvO1xuXG4gICAgaWYoIWdldEluc2lkZS50ZXN0KG5vZGUpKSB7XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gdXJpVGVzdC50ZXN0KHN0cmlwQnJhY2tldHMuZXhlYyhnZXRJbnNpZGUuZXhlYyhub2RlKVsxXSlbMV0pO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgICBpc0FkZHJlc3M6IGlzQWRkcmVzcyxcbiAgICBpc1RyeXRlczogaXNUcnl0ZXMsXG4gICAgaXNOaW5lc1RyeXRlczogaXNOaW5lc1RyeXRlcyxcbiAgICBpc1ZhbHVlOiBpc1ZhbHVlLFxuICAgIGlzSGFzaDogaXNIYXNoLFxuICAgIGlzVHJhbnNmZXJzQXJyYXk6IGlzVHJhbnNmZXJzQXJyYXksXG4gICAgaXNBcnJheU9mSGFzaGVzOiBpc0FycmF5T2ZIYXNoZXMsXG4gICAgaXNBcnJheU9mVHJ5dGVzOiBpc0FycmF5T2ZUcnl0ZXMsXG4gICAgaXNBcnJheU9mQXR0YWNoZWRUcnl0ZXM6IGlzQXJyYXlPZkF0dGFjaGVkVHJ5dGVzLFxuICAgIGlzQXJyYXlPZlR4T2JqZWN0czogaXNBcnJheU9mVHhPYmplY3RzLFxuICAgIGlzSW5wdXRzOiBpc0lucHV0cyxcbiAgICBpc1N0cmluZzogaXNTdHJpbmcsXG4gICAgaXNOdW06IGlzTnVtLFxuICAgIGlzQXJyYXk6IGlzQXJyYXksXG4gICAgaXNPYmplY3Q6IGlzT2JqZWN0LFxuICAgIGlzVXJpOiBpc1VyaVxufVxuIiwidmFyIGlucHV0VmFsaWRhdG9yICA9ICAgcmVxdWlyZShcIi4vaW5wdXRWYWxpZGF0b3JcIik7XG52YXIgQ3VybCAgICAgICAgICAgID0gICByZXF1aXJlKFwiLi4vY3J5cHRvL2N1cmwvY3VybFwiKTtcbnZhciBLZXJsICAgICAgICAgICAgPSAgIHJlcXVpcmUoXCIuLi9jcnlwdG8va2VybC9rZXJsXCIpO1xudmFyIENvbnZlcnRlciAgICAgICA9ICAgcmVxdWlyZShcIi4uL2NyeXB0by9jb252ZXJ0ZXIvY29udmVydGVyXCIpO1xudmFyIFNpZ25pbmcgICAgICAgICA9ICAgcmVxdWlyZShcIi4uL2NyeXB0by9zaWduaW5nL3NpZ25pbmdcIik7XG52YXIgQ3J5cHRvSlMgICAgICAgID0gICByZXF1aXJlKFwiY3J5cHRvLWpzXCIpO1xudmFyIGFzY2lpICAgICAgICAgICA9ICAgcmVxdWlyZShcIi4vYXNjaWlUb1RyeXRlc1wiKTtcbnZhciBleHRyYWN0SnNvbiAgICAgPSAgIHJlcXVpcmUoXCIuL2V4dHJhY3RKc29uXCIpO1xuXG5cbi8qKlxuKiAgIFRhYmxlIG9mIElPVEEgVW5pdHMgYmFzZWQgb2ZmIG9mIHRoZSBzdGFuZGFyZCBTeXN0ZW0gb2YgVW5pdHNcbioqL1xudmFyIHVuaXRNYXAgPSB7XG4gICAgJ2knICAgOiAgIDEsXG4gICAgJ0tpJyAgOiAgIDEwMDAsXG4gICAgJ01pJyAgOiAgIDEwMDAwMDAsXG4gICAgJ0dpJyAgOiAgIDEwMDAwMDAwMDAsXG4gICAgJ1RpJyAgOiAgIDEwMDAwMDAwMDAwMDAsXG4gICAgJ1BpJyAgOiAgIDEwMDAwMDAwMDAwMDAwMDAgIC8vIEZvciB0aGUgdmVyeSwgdmVyeSByaWNoXG59XG5cbi8qKlxuKiAgIGNvbnZlcnRzIElPVEEgdW5pdHNcbipcbiogICBAbWV0aG9kIGNvbnZlcnRVbml0c1xuKiAgIEBwYXJhbSB7c3RyaW5nIHx8IGludCB8fCBmbG9hdH0gdmFsdWVcbiogICBAcGFyYW0ge3N0cmluZ30gZnJvbVVuaXRcbiogICBAcGFyYW0ge3N0cmluZ30gdG9Vbml0XG4qICAgQHJldHVybnMge2ludGVnZXJ9IGNvbnZlcnRlZFxuKiovXG52YXIgY29udmVydFVuaXRzID0gZnVuY3Rpb24odmFsdWUsIGZyb21Vbml0LCB0b1VuaXQpIHtcblxuICAgIC8vIENoZWNrIGlmIHdyb25nIHVuaXQgcHJvdmlkZWRcbiAgICBpZiAodW5pdE1hcFtmcm9tVW5pdF0gPT09IHVuZGVmaW5lZCB8fCB1bml0TWFwW3RvVW5pdF0gPT09IHVuZGVmaW5lZCkge1xuXG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcIkludmFsaWQgdW5pdCBwcm92aWRlZFwiKTtcbiAgICB9XG5cbiAgICB2YXIgYWZ0ZXJDb21tYSA9IFN0cmluZyh2YWx1ZSkubWF0Y2goL1xcLihbXFxkXSspJC8pO1xuXG4gICAgaWYgKGFmdGVyQ29tbWEgJiYgYWZ0ZXJDb21tYVsxXS5sZW5ndGggPiBTdHJpbmcodW5pdE1hcFtmcm9tVW5pdF0pLmxlbmd0aCAtIDEpIHtcblxuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoXCJUb28gbWFueSBkaWdpdHMgYWZ0ZXIgY29tbWFcIik7XG4gICAgfVxuXG4gICAgLy8gSWYgbm90IHZhbGlkIHZhbHVlLCB0aHJvdyBlcnJvclxuICAgIGlmICghaW5wdXRWYWxpZGF0b3IuaXNOdW0odmFsdWUpKSB7XG5cbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiSW52YWxpZCB2YWx1ZVwiKTtcbiAgICB9XG5cblxuICAgIHZhciBmbG9hdFZhbHVlID0gcGFyc2VGbG9hdCh2YWx1ZSk7XG5cbiAgICB2YXIgY29udmVydGVkID0gKGZsb2F0VmFsdWUgKiB1bml0TWFwW2Zyb21Vbml0XSkgLyB1bml0TWFwW3RvVW5pdF07XG5cbiAgICByZXR1cm4gY29udmVydGVkO1xufVxuXG4vKipcbiogICBHZW5lcmF0ZXMgdGhlIDktdHJ5dGUgY2hlY2tzdW0gb2YgYW4gYWRkcmVzc1xuKlxuKiAgIEBtZXRob2QgYWRkQ2hlY2tzdW1cbiogICBAcGFyYW0ge3N0cmluZyB8IGxpc3R9IGlucHV0VmFsdWVcbiogICBAcGFyYW0ge2ludH0gY2hlY2tzdW1MZW5ndGhcbkAgICBAcGFyYW0ge2Jvb2x9IGlzQWRkcmVzcyBkZWZhdWx0IGlzIHRydWVcbiogICBAcmV0dXJucyB7c3RyaW5nIHwgbGlzdH0gYWRkcmVzcyAod2l0aCBjaGVja3N1bSlcbioqL1xudmFyIGFkZENoZWNrc3VtID0gZnVuY3Rpb24oaW5wdXRWYWx1ZSwgY2hlY2tzdW1MZW5ndGgsIGlzQWRkcmVzcykge1xuXG4gICAgLy8gY2hlY2tzdW0gbGVuZ3RoIGlzIGVpdGhlciB1c2VyIGRlZmluZWQsIG9yIDkgdHJ5dGVzXG4gICAgdmFyIGNoZWNrc3VtTGVuZ3RoID0gY2hlY2tzdW1MZW5ndGggfHwgOTtcbiAgICB2YXIgaXNBZGRyZXNzID0gKGlzQWRkcmVzcyAhPT0gZmFsc2UpO1xuXG4gICAgLy8gdGhlIGxlbmd0aCBvZiB0aGUgdHJ5dGVzIHRvIGJlIHZhbGlkYXRlZFxuICAgIHZhciB2YWxpZGF0aW9uTGVuZ3RoID0gaXNBZGRyZXNzID8gODEgOiBudWxsO1xuXG4gICAgdmFyIGlzU2luZ2xlSW5wdXQgPSBpbnB1dFZhbGlkYXRvci5pc1N0cmluZyggaW5wdXRWYWx1ZSApO1xuXG4gICAgLy8gSWYgb25seSBzaW5nbGUgYWRkcmVzcywgdHVybiBpdCBpbnRvIGFuIGFycmF5XG4gICAgaWYgKCBpc1NpbmdsZUlucHV0ICkgaW5wdXRWYWx1ZSA9IG5ldyBBcnJheSggaW5wdXRWYWx1ZSApO1xuXG4gICAgdmFyIGlucHV0c1dpdGhDaGVja3N1bSA9IFtdO1xuXG4gICAgaW5wdXRWYWx1ZS5mb3JFYWNoKGZ1bmN0aW9uKHRoaXNWYWx1ZSkge1xuXG4gICAgICAgIC8vIGNoZWNrIGlmIGNvcnJlY3QgdHJ5dGVzXG4gICAgICAgIGlmICghaW5wdXRWYWxpZGF0b3IuaXNUcnl0ZXModGhpc1ZhbHVlLCB2YWxpZGF0aW9uTGVuZ3RoKSkge1xuICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKFwiSW52YWxpZCBpbnB1dFwiKTtcbiAgICAgICAgfVxuXG4gICAgICAgIHZhciBrZXJsID0gbmV3IEtlcmwoKTtcbiAgICAgICAga2VybC5pbml0aWFsaXplKCk7XG5cbiAgICAgICAgLy8gQWRkcmVzcyB0cml0c1xuICAgICAgICB2YXIgYWRkcmVzc1RyaXRzID0gQ29udmVydGVyLnRyaXRzKHRoaXNWYWx1ZSk7XG5cbiAgICAgICAgLy8gQ2hlY2tzdW0gdHJpdHNcbiAgICAgICAgdmFyIGNoZWNrc3VtVHJpdHMgPSBbXTtcblxuICAgICAgICAvLyBBYnNvcmIgYWRkcmVzcyB0cml0c1xuICAgICAgICBrZXJsLmFic29yYihhZGRyZXNzVHJpdHMsIDAsIGFkZHJlc3NUcml0cy5sZW5ndGgpO1xuXG4gICAgICAgIC8vIFNxdWVlemUgY2hlY2tzdW0gdHJpdHNcbiAgICAgICAga2VybC5zcXVlZXplKGNoZWNrc3VtVHJpdHMsIDAsIEN1cmwuSEFTSF9MRU5HVEgpO1xuXG4gICAgICAgIC8vIEZpcnN0IDkgdHJ5dGVzIGFzIGNoZWNrc3VtXG4gICAgICAgIHZhciBjaGVja3N1bSA9IENvbnZlcnRlci50cnl0ZXMoIGNoZWNrc3VtVHJpdHMgKS5zdWJzdHJpbmcoIDgxIC0gY2hlY2tzdW1MZW5ndGgsIDgxICk7XG4gICAgICAgIGlucHV0c1dpdGhDaGVja3N1bS5wdXNoKCB0aGlzVmFsdWUgKyBjaGVja3N1bSApO1xuICAgIH0pO1xuXG4gICAgaWYgKGlzU2luZ2xlSW5wdXQpIHtcblxuICAgICAgICByZXR1cm4gaW5wdXRzV2l0aENoZWNrc3VtWyAwIF07XG5cbiAgICB9IGVsc2Uge1xuXG4gICAgICAgIHJldHVybiBpbnB1dHNXaXRoQ2hlY2tzdW07XG5cbiAgICB9XG59XG5cbi8qKlxuKiAgIFJlbW92ZXMgdGhlIDktdHJ5dGUgY2hlY2tzdW0gb2YgYW4gYWRkcmVzc1xuKlxuKiAgIEBtZXRob2Qgbm9DaGVja3N1bVxuKiAgIEBwYXJhbSB7c3RyaW5nIHwgbGlzdH0gYWRkcmVzc1xuKiAgIEByZXR1cm5zIHtzdHJpbmcgfCBsaXN0fSBhZGRyZXNzICh3aXRob3V0IGNoZWNrc3VtKVxuKiovXG52YXIgbm9DaGVja3N1bSA9IGZ1bmN0aW9uKGFkZHJlc3MpIHtcblxuICAgIHZhciBpc1NpbmdsZUFkZHJlc3MgPSBpbnB1dFZhbGlkYXRvci5pc1N0cmluZyhhZGRyZXNzKVxuXG4gICAgLy8gSWYgb25seSBzaW5nbGUgYWRkcmVzcywgdHVybiBpdCBpbnRvIGFuIGFycmF5XG4gICAgaWYgKGlzU2luZ2xlQWRkcmVzcykgYWRkcmVzcyA9IG5ldyBBcnJheShhZGRyZXNzKTtcblxuICAgIHZhciBhZGRyZXNzZXNXaXRoQ2hlY2tzdW0gPSBbXTtcblxuICAgIGFkZHJlc3MuZm9yRWFjaChmdW5jdGlvbih0aGlzQWRkcmVzcykge1xuICAgICAgICBhZGRyZXNzZXNXaXRoQ2hlY2tzdW0ucHVzaCh0aGlzQWRkcmVzcy5zbGljZSgwLCA4MSkpXG4gICAgfSlcblxuICAgIC8vIHJldHVybiBlaXRoZXIgc3RyaW5nIG9yIHRoZSBsaXN0XG4gICAgaWYgKGlzU2luZ2xlQWRkcmVzcykge1xuXG4gICAgICAgIHJldHVybiBhZGRyZXNzZXNXaXRoQ2hlY2tzdW1bMF07XG5cbiAgICB9IGVsc2Uge1xuXG4gICAgICAgIHJldHVybiBhZGRyZXNzZXNXaXRoQ2hlY2tzdW07XG5cbiAgICB9XG59XG5cbi8qKlxuKiAgIFZhbGlkYXRlcyB0aGUgY2hlY2tzdW0gb2YgYW4gYWRkcmVzc1xuKlxuKiAgIEBtZXRob2QgaXNWYWxpZENoZWNrc3VtXG4qICAgQHBhcmFtIHtzdHJpbmd9IGFkZHJlc3NXaXRoQ2hlY2tzdW1cbiogICBAcmV0dXJucyB7Ym9vbH1cbioqL1xudmFyIGlzVmFsaWRDaGVja3N1bSA9IGZ1bmN0aW9uKGFkZHJlc3NXaXRoQ2hlY2tzdW0pIHtcblxuICAgIHZhciBhZGRyZXNzV2l0aG91dENoZWNrc3VtID0gbm9DaGVja3N1bShhZGRyZXNzV2l0aENoZWNrc3VtKTtcblxuICAgIHZhciBuZXdDaGVja3N1bSA9IGFkZENoZWNrc3VtKGFkZHJlc3NXaXRob3V0Q2hlY2tzdW0pO1xuXG4gICAgcmV0dXJuIG5ld0NoZWNrc3VtID09PSBhZGRyZXNzV2l0aENoZWNrc3VtO1xufVxuXG4vKipcbiogICBDb252ZXJ0cyB0cmFuc2FjdGlvbiB0cnl0ZXMgb2YgMjY3MyB0cnl0ZXMgaW50byBhIHRyYW5zYWN0aW9uIG9iamVjdFxuKlxuKiAgIEBtZXRob2QgdHJhbnNhY3Rpb25PYmplY3RcbiogICBAcGFyYW0ge3N0cmluZ30gdHJ5dGVzXG4qICAgQHJldHVybnMge1N0cmluZ30gdHJhbnNhY3Rpb25PYmplY3RcbioqL1xudmFyIHRyYW5zYWN0aW9uT2JqZWN0ID0gZnVuY3Rpb24odHJ5dGVzKSB7XG5cbiAgICBpZiAoIXRyeXRlcykgcmV0dXJuO1xuXG4gICAgLy8gdmFsaWRpdHkgY2hlY2tcbiAgICBmb3IgKHZhciBpID0gMjI3OTsgaSA8IDIyOTU7IGkrKykge1xuXG4gICAgICAgIGlmICh0cnl0ZXMuY2hhckF0KGkpICE9PSBcIjlcIikge1xuXG4gICAgICAgICAgICByZXR1cm4gbnVsbDtcblxuICAgICAgICB9XG4gICAgfVxuXG4gICAgdmFyIHRoaXNUcmFuc2FjdGlvbiA9IHt9O1xuICAgIHZhciB0cmFuc2FjdGlvblRyaXRzID0gQ29udmVydGVyLnRyaXRzKHRyeXRlcyk7XG4gICAgdmFyIGhhc2ggPSBbXTtcblxuICAgIHZhciBjdXJsID0gbmV3IEN1cmwoKTtcblxuICAgIC8vIGdlbmVyYXRlIHRoZSBjb3JyZWN0IHRyYW5zYWN0aW9uIGhhc2hcbiAgICBjdXJsLmluaXRpYWxpemUoKTtcbiAgICBjdXJsLmFic29yYih0cmFuc2FjdGlvblRyaXRzLCAwLCB0cmFuc2FjdGlvblRyaXRzLmxlbmd0aCk7XG4gICAgY3VybC5zcXVlZXplKGhhc2gsIDAsIDI0Myk7XG5cbiAgICB0aGlzVHJhbnNhY3Rpb24uaGFzaCA9IENvbnZlcnRlci50cnl0ZXMoaGFzaCk7XG4gICAgdGhpc1RyYW5zYWN0aW9uLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudCA9IHRyeXRlcy5zbGljZSgwLCAyMTg3KTtcbiAgICB0aGlzVHJhbnNhY3Rpb24uYWRkcmVzcyA9IHRyeXRlcy5zbGljZSgyMTg3LCAyMjY4KTtcbiAgICB0aGlzVHJhbnNhY3Rpb24udmFsdWUgPSBDb252ZXJ0ZXIudmFsdWUodHJhbnNhY3Rpb25Ucml0cy5zbGljZSg2ODA0LCA2ODM3KSk7XG4gICAgdGhpc1RyYW5zYWN0aW9uLm9ic29sZXRlVGFnID0gdHJ5dGVzLnNsaWNlKDIyOTUsIDIzMjIpO1xuICAgIHRoaXNUcmFuc2FjdGlvbi50aW1lc3RhbXAgPSBDb252ZXJ0ZXIudmFsdWUodHJhbnNhY3Rpb25Ucml0cy5zbGljZSg2OTY2LCA2OTkzKSk7XG4gICAgdGhpc1RyYW5zYWN0aW9uLmN1cnJlbnRJbmRleCA9IENvbnZlcnRlci52YWx1ZSh0cmFuc2FjdGlvblRyaXRzLnNsaWNlKDY5OTMsIDcwMjApKTtcbiAgICB0aGlzVHJhbnNhY3Rpb24ubGFzdEluZGV4ID0gQ29udmVydGVyLnZhbHVlKHRyYW5zYWN0aW9uVHJpdHMuc2xpY2UoNzAyMCwgNzA0NykpO1xuICAgIHRoaXNUcmFuc2FjdGlvbi5idW5kbGUgPSB0cnl0ZXMuc2xpY2UoMjM0OSwgMjQzMCk7XG4gICAgdGhpc1RyYW5zYWN0aW9uLnRydW5rVHJhbnNhY3Rpb24gPSB0cnl0ZXMuc2xpY2UoMjQzMCwgMjUxMSk7XG4gICAgdGhpc1RyYW5zYWN0aW9uLmJyYW5jaFRyYW5zYWN0aW9uID0gdHJ5dGVzLnNsaWNlKDI1MTEsIDI1OTIpO1xuXG4gICAgdGhpc1RyYW5zYWN0aW9uLnRhZyA9IHRyeXRlcy5zbGljZSgyNTkyLCAyNjE5KTtcbiAgICB0aGlzVHJhbnNhY3Rpb24uYXR0YWNobWVudFRpbWVzdGFtcCA9IENvbnZlcnRlci52YWx1ZSh0cmFuc2FjdGlvblRyaXRzLnNsaWNlKDc4NTcsIDc4ODQpKTtcbiAgICB0aGlzVHJhbnNhY3Rpb24uYXR0YWNobWVudFRpbWVzdGFtcExvd2VyQm91bmQgPSBDb252ZXJ0ZXIudmFsdWUodHJhbnNhY3Rpb25Ucml0cy5zbGljZSg3ODg0LCA3OTExKSk7XG4gICAgdGhpc1RyYW5zYWN0aW9uLmF0dGFjaG1lbnRUaW1lc3RhbXBVcHBlckJvdW5kID0gQ29udmVydGVyLnZhbHVlKHRyYW5zYWN0aW9uVHJpdHMuc2xpY2UoNzkxMSwgNzkzOCkpO1xuICAgIHRoaXNUcmFuc2FjdGlvbi5ub25jZSA9IHRyeXRlcy5zbGljZSgyNjQ2LCAyNjczKTtcblxuICAgIHJldHVybiB0aGlzVHJhbnNhY3Rpb247XG59XG5cbi8qKlxuKiAgIENvbnZlcnRzIGEgdHJhbnNhY3Rpb24gb2JqZWN0IGludG8gdHJ5dGVzXG4qXG4qICAgQG1ldGhvZCB0cmFuc2FjdGlvblRyeXRlc1xuKiAgIEBwYXJhbSB7b2JqZWN0fSB0cmFuc2FjdGlvblRyeXRlc1xuKiAgIEByZXR1cm5zIHtTdHJpbmd9IHRyeXRlc1xuKiovXG52YXIgdHJhbnNhY3Rpb25Ucnl0ZXMgPSBmdW5jdGlvbih0cmFuc2FjdGlvbikge1xuXG4gICAgdmFyIHZhbHVlVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModHJhbnNhY3Rpb24udmFsdWUpO1xuICAgIHdoaWxlICh2YWx1ZVRyaXRzLmxlbmd0aCA8IDgxKSB7XG4gICAgICAgIHZhbHVlVHJpdHNbdmFsdWVUcml0cy5sZW5ndGhdID0gMDtcbiAgICB9XG5cbiAgICB2YXIgdGltZXN0YW1wVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModHJhbnNhY3Rpb24udGltZXN0YW1wKTtcbiAgICB3aGlsZSAodGltZXN0YW1wVHJpdHMubGVuZ3RoIDwgMjcpIHtcbiAgICAgICAgdGltZXN0YW1wVHJpdHNbdGltZXN0YW1wVHJpdHMubGVuZ3RoXSA9IDA7XG4gICAgfVxuXG4gICAgdmFyIGN1cnJlbnRJbmRleFRyaXRzID0gQ29udmVydGVyLnRyaXRzKHRyYW5zYWN0aW9uLmN1cnJlbnRJbmRleCk7XG4gICAgd2hpbGUgKGN1cnJlbnRJbmRleFRyaXRzLmxlbmd0aCA8IDI3KSB7XG4gICAgICAgIGN1cnJlbnRJbmRleFRyaXRzW2N1cnJlbnRJbmRleFRyaXRzLmxlbmd0aF0gPSAwO1xuICAgIH1cblxuICAgIHZhciBsYXN0SW5kZXhUcml0cyA9IENvbnZlcnRlci50cml0cyh0cmFuc2FjdGlvbi5sYXN0SW5kZXgpO1xuICAgIHdoaWxlIChsYXN0SW5kZXhUcml0cy5sZW5ndGggPCAyNykge1xuICAgICAgICBsYXN0SW5kZXhUcml0c1tsYXN0SW5kZXhUcml0cy5sZW5ndGhdID0gMDtcbiAgICB9XG5cbiAgICB2YXIgYXR0YWNobWVudFRpbWVzdGFtcFRyaXRzID0gQ29udmVydGVyLnRyaXRzKHRyYW5zYWN0aW9uLmF0dGFjaG1lbnRUaW1lc3RhbXAgfHwgMCk7XG4gICAgd2hpbGUgKGF0dGFjaG1lbnRUaW1lc3RhbXBUcml0cy5sZW5ndGggPCAyNykge1xuICAgICAgICBhdHRhY2htZW50VGltZXN0YW1wVHJpdHNbYXR0YWNobWVudFRpbWVzdGFtcFRyaXRzLmxlbmd0aF0gPSAwO1xuICAgIH1cblxuICAgIHZhciBhdHRhY2htZW50VGltZXN0YW1wTG93ZXJCb3VuZFRyaXRzID0gQ29udmVydGVyLnRyaXRzKHRyYW5zYWN0aW9uLmF0dGFjaG1lbnRUaW1lc3RhbXBMb3dlckJvdW5kIHx8IDApO1xuICAgIHdoaWxlIChhdHRhY2htZW50VGltZXN0YW1wTG93ZXJCb3VuZFRyaXRzLmxlbmd0aCA8IDI3KSB7XG4gICAgICAgIGF0dGFjaG1lbnRUaW1lc3RhbXBMb3dlckJvdW5kVHJpdHNbYXR0YWNobWVudFRpbWVzdGFtcExvd2VyQm91bmRUcml0cy5sZW5ndGhdID0gMDtcbiAgICB9XG5cbiAgICB2YXIgYXR0YWNobWVudFRpbWVzdGFtcFVwcGVyQm91bmRUcml0cyA9IENvbnZlcnRlci50cml0cyh0cmFuc2FjdGlvbi5hdHRhY2htZW50VGltZXN0YW1wVXBwZXJCb3VuZCB8fCAwKTtcbiAgICB3aGlsZSAoYXR0YWNobWVudFRpbWVzdGFtcFVwcGVyQm91bmRUcml0cy5sZW5ndGggPCAyNykge1xuICAgICAgICBhdHRhY2htZW50VGltZXN0YW1wVXBwZXJCb3VuZFRyaXRzW2F0dGFjaG1lbnRUaW1lc3RhbXBVcHBlckJvdW5kVHJpdHMubGVuZ3RoXSA9IDA7XG4gICAgfVxuXG4gICAgdHJhbnNhY3Rpb24udGFnID0gdHJhbnNhY3Rpb24udGFnIHx8IHRyYW5zYWN0aW9uLm9ic29sZXRlVGFnO1xuXG4gICAgcmV0dXJuIHRyYW5zYWN0aW9uLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudFxuICAgICsgdHJhbnNhY3Rpb24uYWRkcmVzc1xuICAgICsgQ29udmVydGVyLnRyeXRlcyh2YWx1ZVRyaXRzKVxuICAgICsgdHJhbnNhY3Rpb24ub2Jzb2xldGVUYWdcbiAgICArIENvbnZlcnRlci50cnl0ZXModGltZXN0YW1wVHJpdHMpXG4gICAgKyBDb252ZXJ0ZXIudHJ5dGVzKGN1cnJlbnRJbmRleFRyaXRzKVxuICAgICsgQ29udmVydGVyLnRyeXRlcyhsYXN0SW5kZXhUcml0cylcbiAgICArIHRyYW5zYWN0aW9uLmJ1bmRsZVxuICAgICsgdHJhbnNhY3Rpb24udHJ1bmtUcmFuc2FjdGlvblxuICAgICsgdHJhbnNhY3Rpb24uYnJhbmNoVHJhbnNhY3Rpb25cbiAgICArIHRyYW5zYWN0aW9uLnRhZ1xuICAgICsgQ29udmVydGVyLnRyeXRlcyhhdHRhY2htZW50VGltZXN0YW1wVHJpdHMpXG4gICAgKyBDb252ZXJ0ZXIudHJ5dGVzKGF0dGFjaG1lbnRUaW1lc3RhbXBMb3dlckJvdW5kVHJpdHMpXG4gICAgKyBDb252ZXJ0ZXIudHJ5dGVzKGF0dGFjaG1lbnRUaW1lc3RhbXBVcHBlckJvdW5kVHJpdHMpXG4gICAgKyB0cmFuc2FjdGlvbi5ub25jZTtcbn1cblxuLyoqXG4qICAgQ2F0ZWdvcml6ZXMgYSBsaXN0IG9mIHRyYW5zZmVycyBiZXR3ZWVuIHNlbnQgYW5kIHJlY2VpdmVkXG4qXG4qICAgQG1ldGhvZCBjYXRlZ29yaXplVHJhbnNmZXJzXG4qICAgQHBhcmFtIHtvYmplY3R9IHRyYW5zZmVycyBUcmFuc2ZlcnMgKGJ1bmRsZXMpXG4qICAgQHBhcmFtIHtsaXN0fSBhZGRyZXNzZXMgTGlzdCBvZiBhZGRyZXNzZXMgdGhhdCBiZWxvbmcgdG8gdGhlIHVzZXJcbiogICBAcmV0dXJucyB7U3RyaW5nfSB0cnl0ZXNcbioqL1xudmFyIGNhdGVnb3JpemVUcmFuc2ZlcnMgPSBmdW5jdGlvbih0cmFuc2ZlcnMsIGFkZHJlc3Nlcykge1xuXG4gICAgdmFyIGNhdGVnb3JpemVkID0ge1xuICAgICAgICAnc2VudCcgICAgICA6IFtdLFxuICAgICAgICAncmVjZWl2ZWQnICA6IFtdXG4gICAgfVxuXG4gICAgLy8gSXRlcmF0ZSBvdmVyIGFsbCBidW5kbGVzIGFuZCBzb3J0IHRoZW0gYmV0d2VlbiBpbmNvbWluZyBhbmQgb3V0Z29pbmcgdHJhbnNmZXJzXG4gICAgdHJhbnNmZXJzLmZvckVhY2goZnVuY3Rpb24oYnVuZGxlKSB7XG5cbiAgICAgICAgdmFyIHNwZW50QWxyZWFkeUFkZGVkID0gZmFsc2U7XG5cbiAgICAgICAgLy8gSXRlcmF0ZSBvdmVyIGV2ZXJ5IGJ1bmRsZSBlbnRyeVxuICAgICAgICBidW5kbGUuZm9yRWFjaChmdW5jdGlvbihidW5kbGVFbnRyeSwgYnVuZGxlSW5kZXgpIHtcblxuICAgICAgICAgICAgLy8gSWYgYnVuZGxlIGFkZHJlc3MgaW4gdGhlIGxpc3Qgb2YgYWRkcmVzc2VzIGFzc29jaWF0ZWQgd2l0aCB0aGUgc2VlZFxuICAgICAgICAgICAgLy8gYWRkIHRoZSBidW5kbGUgdG8gdGhlXG4gICAgICAgICAgICBpZiAoYWRkcmVzc2VzLmluZGV4T2YoYnVuZGxlRW50cnkuYWRkcmVzcykgPiAtMSkge1xuXG4gICAgICAgICAgICAgICAgLy8gQ2hlY2sgaWYgaXQncyBhIHJlbWFpbmRlciBhZGRyZXNzXG4gICAgICAgICAgICAgICAgdmFyIGlzUmVtYWluZGVyID0gKGJ1bmRsZUVudHJ5LmN1cnJlbnRJbmRleCA9PT0gYnVuZGxlRW50cnkubGFzdEluZGV4KSAmJiBidW5kbGVFbnRyeS5sYXN0SW5kZXggIT09IDA7XG5cbiAgICAgICAgICAgICAgICAvLyBjaGVjayBpZiBzZW50IHRyYW5zYWN0aW9uXG4gICAgICAgICAgICAgICAgaWYgKGJ1bmRsZUVudHJ5LnZhbHVlIDwgMCAmJiAhc3BlbnRBbHJlYWR5QWRkZWQgJiYgIWlzUmVtYWluZGVyKSB7XG5cbiAgICAgICAgICAgICAgICAgICAgY2F0ZWdvcml6ZWQuc2VudC5wdXNoKGJ1bmRsZSk7XG5cbiAgICAgICAgICAgICAgICAgICAgLy8gdG9vIG1ha2Ugc3VyZSB3ZSBkbyBub3QgYWRkIHRyYW5zYWN0aW9ucyB0d2ljZVxuICAgICAgICAgICAgICAgICAgICBzcGVudEFscmVhZHlBZGRlZCA9IHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIC8vIGNoZWNrIGlmIHJlY2VpdmVkIHRyYW5zYWN0aW9uLCBvciAwIHZhbHVlIChtZXNzYWdlKVxuICAgICAgICAgICAgICAgIC8vIGFsc28gbWFrZSBzdXJlIHRoYXQgdGhpcyBpcyBub3QgYSAybmQgdHggZm9yIHNwZW50IGlucHV0c1xuICAgICAgICAgICAgICAgIGVsc2UgaWYgKGJ1bmRsZUVudHJ5LnZhbHVlID49IDAgJiYgIXNwZW50QWxyZWFkeUFkZGVkICYmICFpc1JlbWFpbmRlcikge1xuXG4gICAgICAgICAgICAgICAgICAgIGNhdGVnb3JpemVkLnJlY2VpdmVkLnB1c2goYnVuZGxlKTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9XG4gICAgICAgIH0pXG4gICAgfSlcblxuICAgIHJldHVybiBjYXRlZ29yaXplZDtcbn1cblxuXG4vKipcbiogICBWYWxpZGF0ZXMgdGhlIHNpZ25hdHVyZXNcbipcbiogICBAbWV0aG9kIHZhbGlkYXRlU2lnbmF0dXJlc1xuKiAgIEBwYXJhbSB7YXJyYXl9IHNpZ25lZEJ1bmRsZVxuKiAgIEBwYXJhbSB7c3RyaW5nfSBpbnB1dEFkZHJlc3NcbiogICBAcmV0dXJucyB7Ym9vbH1cbioqL1xudmFyIHZhbGlkYXRlU2lnbmF0dXJlcyA9IGZ1bmN0aW9uKHNpZ25lZEJ1bmRsZSwgaW5wdXRBZGRyZXNzKSB7XG5cblxuICAgIHZhciBidW5kbGVIYXNoO1xuICAgIHZhciBzaWduYXR1cmVGcmFnbWVudHMgPSBbXTtcblxuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgc2lnbmVkQnVuZGxlLmxlbmd0aDsgaSsrKSB7XG5cbiAgICAgICAgaWYgKHNpZ25lZEJ1bmRsZVtpXS5hZGRyZXNzID09PSBpbnB1dEFkZHJlc3MpIHtcblxuICAgICAgICAgICAgYnVuZGxlSGFzaCA9IHNpZ25lZEJ1bmRsZVtpXS5idW5kbGU7XG5cbiAgICAgICAgICAgIC8vIGlmIHdlIHJlYWNoZWQgcmVtYWluZGVyIGJ1bmRsZVxuICAgICAgICAgICAgaWYgKGlucHV0VmFsaWRhdG9yLmlzTmluZXNUcnl0ZXMoc2lnbmVkQnVuZGxlW2ldLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudCkpIHtcbiAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgc2lnbmF0dXJlRnJhZ21lbnRzLnB1c2goc2lnbmVkQnVuZGxlW2ldLnNpZ25hdHVyZU1lc3NhZ2VGcmFnbWVudClcbiAgICAgICAgfVxuICAgIH1cblxuICAgIGlmICghYnVuZGxlSGFzaCkge1xuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfVxuXG4gICAgcmV0dXJuIFNpZ25pbmcudmFsaWRhdGVTaWduYXR1cmVzKGlucHV0QWRkcmVzcywgc2lnbmF0dXJlRnJhZ21lbnRzLCBidW5kbGVIYXNoKTtcbn1cblxuXG4vKipcbiogICBDaGVja3MgaXMgYSBCdW5kbGUgaXMgdmFsaWQuIFZhbGlkYXRlcyBzaWduYXR1cmVzIGFuZCBvdmVyYWxsIHN0cnVjdHVyZS4gSGFzIHRvIGJlIHRhaWwgdHggZmlyc3QuXG4qXG4qICAgQG1ldGhvZCBpc1ZhbGlkQnVuZGxlXG4qICAgQHBhcmFtIHthcnJheX0gYnVuZGxlXG4qICAgQHJldHVybnMge2Jvb2x9IHZhbGlkXG4qKi9cbnZhciBpc0J1bmRsZSA9IGZ1bmN0aW9uKGJ1bmRsZSkge1xuXG4gICAgLy8gSWYgbm90IGNvcnJlY3QgYnVuZGxlXG4gICAgaWYgKCFpbnB1dFZhbGlkYXRvci5pc0FycmF5T2ZUeE9iamVjdHMoYnVuZGxlKSkgcmV0dXJuIGZhbHNlO1xuXG4gICAgdmFyIHRvdGFsU3VtID0gMCwgbGFzdEluZGV4LCBidW5kbGVIYXNoID0gYnVuZGxlWzBdLmJ1bmRsZTtcblxuICAgIC8vIFByZXBhcmUgdG8gYWJzb3JiIHR4cyBhbmQgZ2V0IGJ1bmRsZUhhc2hcbiAgICB2YXIgYnVuZGxlRnJvbVR4cyA9IFtdO1xuXG4gICAgdmFyIGtlcmwgPSBuZXcgS2VybCgpO1xuICAgIGtlcmwuaW5pdGlhbGl6ZSgpO1xuXG4gICAgLy8gUHJlcGFyZSBmb3Igc2lnbmF0dXJlIHZhbGlkYXRpb25cbiAgICB2YXIgc2lnbmF0dXJlc1RvVmFsaWRhdGUgPSBbXTtcblxuICAgIGJ1bmRsZS5mb3JFYWNoKGZ1bmN0aW9uKGJ1bmRsZVR4LCBpbmRleCkge1xuXG4gICAgICAgIHRvdGFsU3VtICs9IGJ1bmRsZVR4LnZhbHVlO1xuXG4gICAgICAgIC8vIGN1cnJlbnRJbmRleCBoYXMgdG8gYmUgZXF1YWwgdG8gdGhlIGluZGV4IGluIHRoZSBhcnJheVxuICAgICAgICBpZiAoYnVuZGxlVHguY3VycmVudEluZGV4ICE9PSBpbmRleCkgcmV0dXJuIGZhbHNlO1xuXG4gICAgICAgIC8vIEdldCB0aGUgdHJhbnNhY3Rpb24gdHJ5dGVzXG4gICAgICAgIHZhciB0aGlzVHhUcnl0ZXMgPSB0cmFuc2FjdGlvblRyeXRlcyhidW5kbGVUeCk7XG5cbiAgICAgICAgLy8gQWJzb3JiIGJ1bmRsZSBoYXNoICsgdmFsdWUgKyB0aW1lc3RhbXAgKyBsYXN0SW5kZXggKyBjdXJyZW50SW5kZXggdHJ5dGVzLlxuICAgICAgICB2YXIgdGhpc1R4VHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModGhpc1R4VHJ5dGVzLnNsaWNlKDIxODcsIDIxODcgKyAxNjIpKTtcbiAgICAgICAga2VybC5hYnNvcmIodGhpc1R4VHJpdHMsIDAsIHRoaXNUeFRyaXRzLmxlbmd0aCk7XG5cbiAgICAgICAgLy8gQ2hlY2sgaWYgaW5wdXQgdHJhbnNhY3Rpb25cbiAgICAgICAgaWYgKGJ1bmRsZVR4LnZhbHVlIDwgMCkge1xuICAgICAgICAgICAgdmFyIHRoaXNBZGRyZXNzID0gYnVuZGxlVHguYWRkcmVzcztcblxuICAgICAgICAgICAgdmFyIG5ld1NpZ25hdHVyZVRvVmFsaWRhdGUgPSB7XG4gICAgICAgICAgICAgICAgJ2FkZHJlc3MnOiB0aGlzQWRkcmVzcyxcbiAgICAgICAgICAgICAgICAnc2lnbmF0dXJlRnJhZ21lbnRzJzogQXJyYXkoYnVuZGxlVHguc2lnbmF0dXJlTWVzc2FnZUZyYWdtZW50KVxuICAgICAgICAgICAgfVxuXG4gICAgICAgICAgICAvLyBGaW5kIHRoZSBzdWJzZXF1ZW50IHR4cyB3aXRoIHRoZSByZW1haW5pbmcgc2lnbmF0dXJlIGZyYWdtZW50XG4gICAgICAgICAgICBmb3IgKHZhciBpID0gaW5kZXg7IGkgPCBidW5kbGUubGVuZ3RoIC0gMTsgaSsrKSB7XG4gICAgICAgICAgICAgICAgdmFyIG5ld0J1bmRsZVR4ID0gYnVuZGxlW2kgKyAxXTtcblxuICAgICAgICAgICAgICAgIC8vIENoZWNrIGlmIG5ldyB0eCBpcyBwYXJ0IG9mIHRoZSBzaWduYXR1cmUgZnJhZ21lbnRcbiAgICAgICAgICAgICAgICBpZiAobmV3QnVuZGxlVHguYWRkcmVzcyA9PT0gdGhpc0FkZHJlc3MgJiYgbmV3QnVuZGxlVHgudmFsdWUgPT09IDApIHtcbiAgICAgICAgICAgICAgICAgICAgbmV3U2lnbmF0dXJlVG9WYWxpZGF0ZS5zaWduYXR1cmVGcmFnbWVudHMucHVzaChuZXdCdW5kbGVUeC5zaWduYXR1cmVNZXNzYWdlRnJhZ21lbnQpO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgc2lnbmF0dXJlc1RvVmFsaWRhdGUucHVzaChuZXdTaWduYXR1cmVUb1ZhbGlkYXRlKTtcbiAgICAgICAgfVxuICAgIH0pO1xuXG4gICAgLy8gQ2hlY2sgZm9yIHRvdGFsIHN1bSwgaWYgbm90IGVxdWFsIDAgcmV0dXJuIGVycm9yXG4gICAgaWYgKHRvdGFsU3VtICE9PSAwKSByZXR1cm4gZmFsc2U7XG5cbiAgICAvLyBnZXQgdGhlIGJ1bmRsZSBoYXNoIGZyb20gdGhlIGJ1bmRsZSB0cmFuc2FjdGlvbnNcbiAgICBrZXJsLnNxdWVlemUoYnVuZGxlRnJvbVR4cywgMCwgQ3VybC5IQVNIX0xFTkdUSCk7XG4gICAgdmFyIGJ1bmRsZUZyb21UeHMgPSBDb252ZXJ0ZXIudHJ5dGVzKGJ1bmRsZUZyb21UeHMpO1xuXG4gICAgLy8gQ2hlY2sgaWYgYnVuZGxlIGhhc2ggaXMgdGhlIHNhbWUgYXMgcmV0dXJuZWQgYnkgdHggb2JqZWN0XG4gICAgaWYgKGJ1bmRsZUZyb21UeHMgIT09IGJ1bmRsZUhhc2gpIHJldHVybiBmYWxzZTtcblxuICAgIC8vIExhc3QgdHggaW4gdGhlIGJ1bmRsZSBzaG91bGQgaGF2ZSBjdXJyZW50SW5kZXggPT09IGxhc3RJbmRleFxuICAgIGlmIChidW5kbGVbYnVuZGxlLmxlbmd0aCAtIDFdLmN1cnJlbnRJbmRleCAhPT0gYnVuZGxlW2J1bmRsZS5sZW5ndGggLSAxXS5sYXN0SW5kZXgpIHJldHVybiBmYWxzZTtcblxuICAgIC8vIFZhbGlkYXRlIHRoZSBzaWduYXR1cmVzXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBzaWduYXR1cmVzVG9WYWxpZGF0ZS5sZW5ndGg7IGkrKykge1xuXG4gICAgICAgIHZhciBpc1ZhbGlkU2lnbmF0dXJlID0gU2lnbmluZy52YWxpZGF0ZVNpZ25hdHVyZXMoc2lnbmF0dXJlc1RvVmFsaWRhdGVbaV0uYWRkcmVzcywgc2lnbmF0dXJlc1RvVmFsaWRhdGVbaV0uc2lnbmF0dXJlRnJhZ21lbnRzLCBidW5kbGVIYXNoKTtcblxuICAgICAgICBpZiAoIWlzVmFsaWRTaWduYXR1cmUpIHJldHVybiBmYWxzZTtcbiAgICB9XG5cbiAgICByZXR1cm4gdHJ1ZTtcbn1cblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gICAgaW5wdXRWYWxpZGF0b3IgICAgICA6IGlucHV0VmFsaWRhdG9yLCAgICBcbiAgICBjb252ZXJ0VW5pdHMgICAgICAgIDogY29udmVydFVuaXRzLFxuICAgIGFkZENoZWNrc3VtICAgICAgICAgOiBhZGRDaGVja3N1bSxcbiAgICBub0NoZWNrc3VtICAgICAgICAgIDogbm9DaGVja3N1bSxcbiAgICBpc1ZhbGlkQ2hlY2tzdW0gICAgIDogaXNWYWxpZENoZWNrc3VtLFxuICAgIHRyYW5zYWN0aW9uT2JqZWN0ICAgOiB0cmFuc2FjdGlvbk9iamVjdCxcbiAgICB0cmFuc2FjdGlvblRyeXRlcyAgIDogdHJhbnNhY3Rpb25Ucnl0ZXMsXG4gICAgY2F0ZWdvcml6ZVRyYW5zZmVycyA6IGNhdGVnb3JpemVUcmFuc2ZlcnMsXG4gICAgdG9Ucnl0ZXMgICAgICAgICAgICA6IGFzY2lpLnRvVHJ5dGVzLFxuICAgIGZyb21Ucnl0ZXMgICAgICAgICAgOiBhc2NpaS5mcm9tVHJ5dGVzLFxuICAgIGV4dHJhY3RKc29uICAgICAgICAgOiBleHRyYWN0SnNvbixcbiAgICB2YWxpZGF0ZVNpZ25hdHVyZXMgIDogdmFsaWRhdGVTaWduYXR1cmVzLFxuICAgIGlzQnVuZGxlICAgICAgICAgICAgOiBpc0J1bmRsZVxufVxuIiwiY29uc3QgaW5pdEdMID0gcmVxdWlyZSgnLi9pbml0R0wnKTtcbmNvbnN0IG5ld0J1ZmZlciA9IHJlcXVpcmUoJy4vbmV3QnVmZmVyJyk7XG5jb25zdCBjcmVhdGVUZXh0dXJlID0gcmVxdWlyZSgnLi90ZXh0dXJlJyk7XG5jb25zdCBTaGFkZXJDb2RlID0gcmVxdWlyZSgnLi9zaGFkZXJjb2RlJyk7XG5cbmZ1bmN0aW9uIF9mcmFtZUJ1ZmZlclNldFRleHR1cmUgKGdsLCBmYm8sIG5UZXh0dXJlLCBkaW0pIHtcbiAgZ2wuYmluZEZyYW1lYnVmZmVyKGdsLkZSQU1FQlVGRkVSLCBmYm8pO1xuICAvLyBUeXBlcyBhcnJheXMgc3BlZWQgdGhpcyB1cCB0cmVtZW5kb3VzbHkuXG4gIC8vdmFyIG5UZXh0dXJlID0gY3JlYXRlVGV4dHVyZShnbCwgbmV3IEludDMyQXJyYXkobGVuZ3RoKSwgZGltKTtcblxuICBnbC5mcmFtZWJ1ZmZlclRleHR1cmUyRChnbC5GUkFNRUJVRkZFUiwgZ2wuQ09MT1JfQVRUQUNITUVOVDAsIGdsLlRFWFRVUkVfMkQsIG5UZXh0dXJlLCAwKTtcblxuICAvLyBUZXN0IGZvciBtb2JpbGUgYnVnIE1ETi0+V2ViR0xfYmVzdF9wcmFjdGljZXMsIGJ1bGxldCA3XG4gIHZhciBmcmFtZUJ1ZmZlclN0YXR1cyA9IChnbC5jaGVja0ZyYW1lYnVmZmVyU3RhdHVzKGdsLkZSQU1FQlVGRkVSKSA9PSBnbC5GUkFNRUJVRkZFUl9DT01QTEVURSk7XG5cbiAgaWYgKCFmcmFtZUJ1ZmZlclN0YXR1cylcbiAgICB0aHJvdyBuZXcgRXJyb3IoJ3R1cmJvanM6IEVycm9yIGF0dGFjaGluZyBmbG9hdCB0ZXh0dXJlIHRvIGZyYW1lYnVmZmVyLiBZb3VyIGRldmljZSBpcyBwcm9iYWJseSBpbmNvbXBhdGlibGUuIEVycm9yIGluZm86ICcgKyBmcmFtZUJ1ZmZlclN0YXR1cy5tZXNzYWdlKTtcbn1cbmZ1bmN0aW9uIGFsbG9jIChzeikge1xuICAvLyBBIHNhbmUgbGltaXQgZm9yIG1vc3QgR1BVcyBvdXQgdGhlcmUuXG4gIC8vIEpTIGZhbGxzIGFwYXJ0IGJlZm9yZSBHTFNMIGxpbWl0cyBjb3VsZCBldmVyIGJlIHJlYWNoZWQuXG5cbiAgdmFyIG5zID0gTWF0aC5wb3coTWF0aC5wb3coMiwgTWF0aC5jZWlsKE1hdGgubG9nKHN6KSAvIDEuMzg2KSAtIDEpLCAyKTtcbiAgcmV0dXJuIHtcbiAgICAvL2RhdGEgOiBuZXcgSW50MzJBcnJheShucyAqIDE2KSxcbiAgICBkYXRhIDogbmV3IEludDMyQXJyYXkoc3opLFxuICAgIGxlbmd0aCA6IHN6XG4gIH07XG59XG5jb25zdCBfYmluZEJ1ZmZlcnMgPSAoZ2wsIGJ1ZmZlcnMsIGF0dHJpYikgPT4ge1xuICBnbC5iaW5kQnVmZmVyKGdsLkFSUkFZX0JVRkZFUiwgYnVmZmVycy50ZXh0dXJlKTtcbiAgZ2wuZW5hYmxlVmVydGV4QXR0cmliQXJyYXkoYXR0cmliLnRleHR1cmUpO1xuICBnbC52ZXJ0ZXhBdHRyaWJQb2ludGVyKGF0dHJpYi50ZXh0dXJlLCAyLCBnbC5GTE9BVCwgZmFsc2UsIDAsIDApO1xuICBnbC5iaW5kQnVmZmVyKGdsLkFSUkFZX0JVRkZFUiwgYnVmZmVycy5wb3NpdGlvbik7XG4gIGdsLmVuYWJsZVZlcnRleEF0dHJpYkFycmF5KGF0dHJpYi5wb3NpdGlvbik7XG4gIGdsLnZlcnRleEF0dHJpYlBvaW50ZXIoYXR0cmliLnBvc2l0aW9uLCAyLCBnbC5GTE9BVCwgZmFsc2UsIDAsIDApO1xuICBnbC5iaW5kQnVmZmVyKGdsLkVMRU1FTlRfQVJSQVlfQlVGRkVSLCBidWZmZXJzLmluZGV4KTtcbn1cbmNvbnN0IF9jcmVhdGVWZXJ0ZXhTaGFkZXIgPSAoZ2wpID0+IHtcbiAgdmFyIHZlcnRleFNoYWRlciA9IGdsLmNyZWF0ZVNoYWRlcihnbC5WRVJURVhfU0hBREVSKTtcbiAgZ2wuc2hhZGVyU291cmNlKHZlcnRleFNoYWRlciwgU2hhZGVyQ29kZS52ZXJ0ZXhTaGFkZXJDb2RlKTtcbiAgZ2wuY29tcGlsZVNoYWRlcih2ZXJ0ZXhTaGFkZXIpO1xuXG4gIC8vIFRoaXMgc2hvdWxkIG5vdCBmYWlsLlxuICBpZiAoIWdsLmdldFNoYWRlclBhcmFtZXRlcih2ZXJ0ZXhTaGFkZXIsIGdsLkNPTVBJTEVfU1RBVFVTKSlcbiAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICBcIlxcbnR1cmJvanM6IENvdWxkIG5vdCBidWlsZCBpbnRlcm5hbCB2ZXJ0ZXggc2hhZGVyIChmYXRhbCkuXFxuXCIgKyBcIlxcblwiICtcbiAgICAgIFwiSU5GTzogPlJFUE9SVDwgVEhJUy4gVGhhdCdzIG91ciBmYXVsdCFcXG5cIiArIFwiXFxuXCIgK1xuICAgICAgXCItLS0gQ09ERSBEVU1QIC0tLVxcblwiICsgU2hhZGVyQ29kZS52ZXJ0ZXhTaGFkZXJDb2RlICsgXCJcXG5cXG5cIiArXG4gICAgICBcIi0tLSBFUlJPUiBMT0cgLS0tXFxuXCIgKyBnbC5nZXRTaGFkZXJJbmZvTG9nKHZlcnRleFNoYWRlcilcbiAgICApO1xuICByZXR1cm4gdmVydGV4U2hhZGVyO1xufVxuY29uc3QgX2NyZWF0ZUZyYWdtZW50U2hhZGVyID0gKGdsLCBjb2RlKSA9PiB7XG4gIHZhciBmcmFnbWVudFNoYWRlciA9IGdsLmNyZWF0ZVNoYWRlcihnbC5GUkFHTUVOVF9TSEFERVIpO1xuXG4gIGdsLnNoYWRlclNvdXJjZShmcmFnbWVudFNoYWRlciwgU2hhZGVyQ29kZS5zdGRsaWIgKyBjb2RlKTtcblxuICBnbC5jb21waWxlU2hhZGVyKGZyYWdtZW50U2hhZGVyKTtcbiAgLy8gVXNlIHRoaXMgb3V0cHV0IHRvIGRlYnVnIHRoZSBzaGFkZXJcbiAgLy8gS2VlcCBpbiBtaW5kIHRoYXQgV2ViR0wgR0xTTCBpcyAqKm11Y2gqKiBzdHJpY3RlciB0aGFuIGUuZy4gT3BlbkdMIEdMU0xcbiAgaWYgKCFnbC5nZXRTaGFkZXJQYXJhbWV0ZXIoZnJhZ21lbnRTaGFkZXIsIGdsLkNPTVBJTEVfU1RBVFVTKSkge1xuICAgIHZhciBMT0MgPSBjb2RlLnNwbGl0KCdcXG4nKTtcbiAgICB2YXIgZGJnTXNnID0gXCJFUlJPUjogQ291bGQgbm90IGJ1aWxkIHNoYWRlciAoZmF0YWwpLlxcblxcbi0tLS0tLS0tLS0tLS0tLS0tLSBLRVJORUwgQ09ERSBEVU1QIC0tLS0tLS0tLS0tLS0tLS0tLVxcblwiXG5cbiAgICBmb3IgKHZhciBubCA9IDA7IG5sIDwgTE9DLmxlbmd0aDsgbmwrKylcbiAgICAgIGRiZ01zZyArPSAoU2hhZGVyQ29kZS5zdGRsaWIuc3BsaXQoJ1xcbicpLmxlbmd0aCArIG5sKSArIFwiPiBcIiArIExPQ1tubF0gKyBcIlxcblwiO1xuXG4gICAgZGJnTXNnICs9IFwiXFxuLS0tLS0tLS0tLS0tLS0tLS0tLS0tIEVSUk9SICBMT0cgLS0tLS0tLS0tLS0tLS0tLS0tLS0tXFxuXCIgKyBnbC5nZXRTaGFkZXJJbmZvTG9nKGZyYWdtZW50U2hhZGVyKVxuXG4gICAgdGhyb3cgbmV3IEVycm9yKGRiZ01zZyk7XG4gIH1cbiAgcmV0dXJuIGZyYWdtZW50U2hhZGVyO1xufVxuY29uc3QgX2ZpbmlzaFJ1biAgPSAoZ2wpID0+IHtcbiAgZ2wuYmluZFZlcnRleEFycmF5KG51bGwpO1xuICBnbC5iaW5kVGV4dHVyZShnbC5URVhUVVJFXzJELCBudWxsKTtcbiAgZ2wuYmluZEZyYW1lYnVmZmVyKGdsLkZSQU1FQlVGRkVSLCBudWxsKTtcbn1cbmNvbnN0IFdlYkdMV29ya2VyID0gKGwsIHMpID0+IHtcblxuICBsZXQgd29ya2VyID0gbmV3IE9iamVjdCgpO1xuICB3b3JrZXIuZ2wgPSBpbml0R0woKTtcbiAgbGV0IGdsID0gd29ya2VyLmdsO1xuXG4gIHdvcmtlci5kaW0gPSB7XG4gICAgeDogbCxcbiAgICB5OiAwXG4gIH07XG4gIGNvbnN0IE1BWElNQUdFU0laRSA9IE1hdGgucG93KGdsLk1BWF9URVhUVVJFX1NJWkUsIDIpICogMC41MDtcbiAgY29uc3QgSU1BR0VfU0laRT0gTWF0aC5mbG9vcihNQVhJTUFHRVNJWkUgLyB3b3JrZXIuZGltLnggLyBzICkgKiB3b3JrZXIuZGltLnggKiBzO1xuICB3b3JrZXIuZGltLnkgPSBJTUFHRV9TSVpFIC8gd29ya2VyLmRpbS54IC8gcyA7XG4gIGxldCBsZW5ndGggPSBJTUFHRV9TSVpFO1xuXG5cbiAgd29ya2VyLnByb2dyYW1zID0gbmV3IE1hcCgpO1xuICB3b3JrZXIuaXB0ID0gYWxsb2MobGVuZ3RoKTtcblxuICAvLyBHUFUgdGV4dHVyZSBidWZmZXIgPSBmcm9tIEpTIHR5cGVkIGFycmF5XG4gIHdvcmtlci5idWZmZXJzID0ge1xuICAgIHBvc2l0aW9uIDogbmV3QnVmZmVyKGdsLCBbIC0xLCAtMSwgMSwgLTEsIDEsIDEsIC0xLCAxIF0pLFxuICAgIHRleHR1cmUgIDogbmV3QnVmZmVyKGdsLCBbICAwLCAgMCwgMSwgIDAsIDEsIDEsICAwLCAxIF0pLFxuICAgIGluZGV4ICAgIDogbmV3QnVmZmVyKGdsLCBbICAxLCAgMiwgMCwgIDMsIDAsIDIgXSwgVWludDE2QXJyYXksIGdsLkVMRU1FTlRfQVJSQVlfQlVGRkVSKVxuICB9O1xuXG4gIHdvcmtlci5hdHRyaWIgPSB7XG4gICAgcG9zaXRpb246IDAsXG4gICAgdGV4dHVyZTogMVxuICB9O1xuXG4gIHdvcmtlci52YW8gPSBnbC5jcmVhdGVWZXJ0ZXhBcnJheSgpO1xuICBnbC5iaW5kVmVydGV4QXJyYXkod29ya2VyLnZhbyk7XG4gIF9iaW5kQnVmZmVycyhnbCwgd29ya2VyLmJ1ZmZlcnMsIHdvcmtlci5hdHRyaWIpO1xuICBnbC5iaW5kVmVydGV4QXJyYXkobnVsbCk7XG4gIHdvcmtlci52ZXJ0ZXhTaGFkZXIgPSBfY3JlYXRlVmVydGV4U2hhZGVyKGdsKTtcbiAgd29ya2VyLmZyYW1lYnVmZmVyID0gZ2wuY3JlYXRlRnJhbWVidWZmZXIoKTtcbiAgd29ya2VyLnRleHR1cmUwID0gY3JlYXRlVGV4dHVyZShnbCwgd29ya2VyLmlwdC5kYXRhLCB3b3JrZXIuZGltKTtcbiAgd29ya2VyLnRleHR1cmUxID0gY3JlYXRlVGV4dHVyZShnbCwgbmV3IEludDMyQXJyYXkobGVuZ3RoKSwgd29ya2VyLmRpbSk7XG4gIHJldHVybiB3b3JrZXI7XG59XG5tb2R1bGUuZXhwb3J0cyA9IHtcbiAgd29ya2VyOiBXZWJHTFdvcmtlcixcbiAgYWRkUHJvZ3JhbTogKHdvcmtlciwgbmFtZSwgY29kZSwgLi4udW5pZm9ybXMpID0+IHtcbiAgICBsZXQgZ2wgPSB3b3JrZXIuZ2w7XG4gICAgbGV0IHZlcnRleFNoYWRlciA9IHdvcmtlci52ZXJ0ZXhTaGFkZXI7XG5cbiAgICB2YXIgZnJhZ21lbnRTaGFkZXIgPSBfY3JlYXRlRnJhZ21lbnRTaGFkZXIod29ya2VyLmdsLCBjb2RlKTtcbiAgICB2YXIgcHJvZ3JhbSA9IGdsLmNyZWF0ZVByb2dyYW0oKTtcblxuICAgIGdsLmF0dGFjaFNoYWRlcihwcm9ncmFtLCB2ZXJ0ZXhTaGFkZXIpO1xuICAgIGdsLmF0dGFjaFNoYWRlcihwcm9ncmFtLCBmcmFnbWVudFNoYWRlcik7XG4gICAgZ2wuYmluZEF0dHJpYkxvY2F0aW9uKHByb2dyYW0sIHdvcmtlci5hdHRyaWIucG9zaXRpb24sICdwb3NpdGlvbicpO1xuICAgIGdsLmJpbmRBdHRyaWJMb2NhdGlvbihwcm9ncmFtLCB3b3JrZXIuYXR0cmliLnRleHR1cmUsICd0ZXh0dXJlJyk7XG4gICAgZ2wubGlua1Byb2dyYW0ocHJvZ3JhbSk7XG4gICAgdmFyIHVfdmFycyA9IG5ldyBNYXAoKTtcbiAgICBmb3IodmFyIHZhcmlhYmxlIG9mIHVuaWZvcm1zKSB7XG4gICAgICB1X3ZhcnMuc2V0KHZhcmlhYmxlLCBnbC5nZXRVbmlmb3JtTG9jYXRpb24ocHJvZ3JhbSwgdmFyaWFibGUpKTtcbiAgICB9XG4gICAgaWYoISF3b3JrZXIucHJvZ3JhbXMuZ2V0KG5hbWUpKSB7XG4gICAgICBjb25zb2xlLmxvZyhcInByb2dyYW0gZXhpc3RzXCIpO1xuICAgIH1cbiAgICB3b3JrZXIucHJvZ3JhbXMuc2V0KG5hbWUsIHtwcm9ncmFtLCB1X3ZhcnN9KTtcbiAgfSxcbiAgICAvKlxuICAgIHVzZTogKG5hbWUpID0+IHtcbiAgfSxcbiAgKi9cbiAgcnVuOiAod29ya2VyLCBuYW1lLCBjb3VudCwgLi4udW5pZm9ybXMpID0+IHtcbiAgICBsZXQgZ2wgPSB3b3JrZXIuZ2w7XG4gICAgbGV0IGluZm8gPSB3b3JrZXIucHJvZ3JhbXMuZ2V0KG5hbWUpO1xuICAgIGxldCBwcm9ncmFtID0gaW5mby5wcm9ncmFtO1xuICAgIGxldCB1X3ZhcnMgPSBpbmZvLnVfdmFycztcbiAgICBpZihwcm9ncmFtID09PSBudWxsKVxuICAgICAgdGhyb3cgbmV3IEVycm9yKFwiTm8gU3VjaCBQcm9ncmFtIVwiKTtcblxuICAgIGlmICghZ2wuZ2V0UHJvZ3JhbVBhcmFtZXRlcihwcm9ncmFtLCBnbC5MSU5LX1NUQVRVUykpXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ3R1cmJvanM6IEZhaWxlZCB0byBsaW5rIEdMU0wgcHJvZ3JhbSBjb2RlLicpO1xuXG4gICAgdmFyIHVUZXh0dXJlID0gZ2wuZ2V0VW5pZm9ybUxvY2F0aW9uKHByb2dyYW0sICd1X3RleHR1cmUnKTtcbiAgICBnbC51c2VQcm9ncmFtKHByb2dyYW0pO1xuXG4gICAgY291bnQgPSBjb3VudCB8fCAxO1xuICAgIHdoaWxlKGNvdW50LS0gPiAwKSB7XG4gICAgICBnbC5iaW5kVGV4dHVyZShnbC5URVhUVVJFXzJELCB3b3JrZXIudGV4dHVyZTApO1xuICAgICAgZ2wuYWN0aXZlVGV4dHVyZShnbC5URVhUVVJFMCk7XG4gICAgICBnbC51bmlmb3JtMWkodVRleHR1cmUsIDApO1xuXG4gICAgICBnbC52aWV3cG9ydCgwLCAwLCB3b3JrZXIuZGltLngsIHdvcmtlci5kaW0ueSk7XG4gICAgICBfZnJhbWVCdWZmZXJTZXRUZXh0dXJlKGdsLCB3b3JrZXIuZnJhbWVidWZmZXIsIHdvcmtlci50ZXh0dXJlMSwgd29ya2VyLmRpbSk7IC8vbmV3XG4gICAgICBnbC5iaW5kVmVydGV4QXJyYXkod29ya2VyLnZhbyk7XG4gICAgICBmb3IodmFyIHVfdiBvZiB1bmlmb3Jtcykge1xuICAgICAgICBnbC51bmlmb3JtMWkodV92YXJzLmdldCh1X3YubiksIHVfdi52KTtcbiAgICAgIH1cbiAgICAgIGdsLmRyYXdFbGVtZW50cyhnbC5UUklBTkdMRVMsIDYsIGdsLlVOU0lHTkVEX1NIT1JULCAwKTtcbiAgICAgIGxldCB0ZXgwID0gd29ya2VyLnRleHR1cmUwO1xuICAgICAgd29ya2VyLnRleHR1cmUwID0gd29ya2VyLnRleHR1cmUxO1xuICAgICAgd29ya2VyLnRleHR1cmUxID0gdGV4MDtcbiAgICB9XG5cbiAgICBfZmluaXNoUnVuKGdsKTtcbiAgfSxcbiAgcmVhZERhdGE6ICh3b3JrZXIsIHgseSxOLE0pID0+IHtcbiAgICBsZXQgZ2wgPSB3b3JrZXIuZ2w7XG4gICAgeCA9IHggfHwgMDtcbiAgICB5ID0geSB8fCAwO1xuICAgIE4gPSBOIHx8IHdvcmtlci5kaW0ueDtcbiAgICBNID0gTSB8fCB3b3JrZXIuZGltLnk7XG4gICAgZ2wuYmluZEZyYW1lYnVmZmVyKGdsLkZSQU1FQlVGRkVSLCB3b3JrZXIuZnJhbWVidWZmZXIpO1xuICAgIGdsLnJlYWRQaXhlbHMoeCwgeSwgTiwgTSwgZ2wuUkdCQV9JTlRFR0VSLCBnbC5JTlQsIHdvcmtlci5pcHQuZGF0YSk7XG4gICAgZ2wuYmluZEZyYW1lYnVmZmVyKGdsLkZSQU1FQlVGRkVSLCBudWxsKTtcbiAgICByZXR1cm4gd29ya2VyLmlwdC5kYXRhLnN1YmFycmF5KDAsIHdvcmtlci5pcHQubGVuZ3RoKTtcbiAgfSxcbiAgd3JpdGVEYXRhOiAod29ya2VyLCBkYXRhKSA9PiB7XG4gICAgbGV0IGdsID0gd29ya2VyLmdsO1xuICAgIGdsLmJpbmRUZXh0dXJlKGdsLlRFWFRVUkVfMkQsIHdvcmtlci50ZXh0dXJlMCk7XG4gICAgZ2wudGV4SW1hZ2UyRChnbC5URVhUVVJFXzJELCAwLCBnbC5SR0JBMzJJLHdvcmtlci5kaW0ueCx3b3JrZXIuZGltLnksIDAsIGdsLlJHQkFfSU5URUdFUiwgZ2wuSU5ULCBkYXRhKTtcbiAgICBnbC5iaW5kVGV4dHVyZShnbC5URVhUVVJFXzJELCBudWxsKTtcbiAgfVxufVxuIiwibW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiAoKSB7XG4gIHZhciBjYW52YXMgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdjYW52YXMnKTtcbiAgLy92YXIgY2FudmFzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2MnKTtcbiAgdmFyIGdsID0gbnVsbDtcbiAgdmFyIGF0dHIgPSB7YWxwaGEgOiBmYWxzZSwgYW50aWFsaWFzIDogZmFsc2V9O1xuXG4gIC8vIFRyeSB0byBncmFiIHRoZSBzdGFuZGFyZCBjb250ZXh0LiBJZiBpdCBmYWlscywgZmFsbGJhY2sgdG8gZXhwZXJpbWVudGFsLlxuICBnbCA9IGNhbnZhcy5nZXRDb250ZXh0KFwid2ViZ2wyXCIsIGF0dHIpIHx8IGNhbnZhcy5nZXRDb250ZXh0KFwiZXhwZXJpbWVudGFsLXdlYmdsMlwiLCBhdHRyKTtcblxuICAvLyBJZiB3ZSBkb24ndCBoYXZlIGEgR0wgY29udGV4dCwgZ2l2ZSB1cCBub3dcbiBpZiAoIWdsKSB7IC8vIGdsIGluc3RhbmNlb2YgV2ViR0xSZW5kZXJpbmdDb250ZXh0KVxuICAgIHRocm93IG5ldyBFcnJvcihcIlVuYWJsZSB0byBpbml0aWFsaXplIFdlYkdMLiBZb3VyIGJyb3dzZXIgbWF5IG5vdCBzdXBwb3J0IGl0LlwiKTtcbiB9XG5cbiAgcmV0dXJuIGdsO1xufVxuIiwibW9kdWxlLmV4cG9ydHMgPSBmdW5jdGlvbiAoZ2wsIGRhdGEsIGYsIGUpIHtcbiAgdmFyIGJ1ZiA9IGdsLmNyZWF0ZUJ1ZmZlcigpO1xuXG4gIGdsLmJpbmRCdWZmZXIoKGUgfHwgZ2wuQVJSQVlfQlVGRkVSKSwgYnVmKTtcbiAgZ2wuYnVmZmVyRGF0YSgoZSB8fCBnbC5BUlJBWV9CVUZGRVIpLCBuZXcgKGYgfHwgRmxvYXQzMkFycmF5KShkYXRhKSwgZ2wuU1RBVElDX0RSQVcpO1xuXG4gIHJldHVybiBidWY7XG59XG4iLCJtb2R1bGUuZXhwb3J0cyA9IHtcbiB2ZXJ0ZXhTaGFkZXJDb2RlOlxuICBgI3ZlcnNpb24gMzAwIGVzXG5sYXlvdXQobG9jYXRpb24gPSAwKSBpbiB2ZWMyIHBvc2l0aW9uO1xubGF5b3V0KGxvY2F0aW9uID0gMSkgaW4gdmVjMiB0ZXh0dXJlO1xub3V0IHZlYzIgcG9zO1xuXG52b2lkIG1haW4odm9pZCkge1xuICBwb3MgPSB0ZXh0dXJlO1xuICBnbF9Qb3NpdGlvbiA9IHZlYzQocG9zaXRpb24ueHksIDAuMCwgMS4wKTtcbn1gLFxuICBzdGRsaWI6XG4gIGAjdmVyc2lvbiAzMDAgZXNcbnByZWNpc2lvbiBoaWdocCBmbG9hdDtcbnByZWNpc2lvbiBoaWdocCBpbnQ7XG5wcmVjaXNpb24gaGlnaHAgaXNhbXBsZXIyRDtcbnVuaWZvcm0gaXNhbXBsZXIyRCB1X3RleHR1cmU7XG5pbiB2ZWMyIHBvcztcbm91dCBpdmVjNCBjb2xvcjtcbi8vb3V0IGludCBpc0ZpbmlzaGVkO1xuXG52ZWMyIHNpemU7XG5pdmVjMiBteV9jb29yZDtcblxudm9pZCBpbml0KHZvaWQpIHtcbiAgLy9zaXplID0gdmVjMih0ZXh0dXJlU2l6ZSh1X3RleHR1cmUsIDApIC0gMSk7XG4gIHNpemUgPSB2ZWMyKHRleHR1cmVTaXplKHVfdGV4dHVyZSwgMCkpO1xuICBteV9jb29yZCA9IGl2ZWMyKHBvcyAqIHNpemUpO1xufVxuXG5pdmVjNCByZWFkKHZvaWQpIHtcbiAgcmV0dXJuIHRleHR1cmUodV90ZXh0dXJlLCBwb3MpO1xufVxuXG5pdmVjNCByZWFkX2F0KGl2ZWMyIGNvb3JkKSB7XG4gIHJldHVybiB0ZXhlbEZldGNoKHVfdGV4dHVyZSwgY29vcmQsIDApO1xufVxuXG52b2lkIGNvbW1pdChpdmVjNCB2YWwpIHtcbiAgY29sb3IgPSB2YWw7XG59XG5gfVxuXG4iLCIvLyBUcmFuc2ZlciBkYXRhIG9udG8gY2xhbXBlZCB0ZXh0dXJlIGFuZCB0dXJuIG9mZiBhbnkgZmlsdGVyaW5nXG5tb2R1bGUuZXhwb3J0cyA9IGZ1bmN0aW9uIGNyZWF0ZVRleHR1cmUoZ2wsIGRhdGEsIGRpbSkge1xuICB2YXIgdGV4dHVyZSA9IGdsLmNyZWF0ZVRleHR1cmUoKTtcblxuICBnbC5iaW5kVGV4dHVyZShnbC5URVhUVVJFXzJELCB0ZXh0dXJlKTtcbiAgZ2wudGV4UGFyYW1ldGVyaShnbC5URVhUVVJFXzJELCBnbC5URVhUVVJFX1dSQVBfUywgZ2wuQ0xBTVBfVE9fRURHRSk7XG4gIGdsLnRleFBhcmFtZXRlcmkoZ2wuVEVYVFVSRV8yRCwgZ2wuVEVYVFVSRV9XUkFQX1QsIGdsLkNMQU1QX1RPX0VER0UpO1xuICBnbC50ZXhQYXJhbWV0ZXJpKGdsLlRFWFRVUkVfMkQsIGdsLlRFWFRVUkVfTUlOX0ZJTFRFUiwgZ2wuTkVBUkVTVCk7XG4gIGdsLnRleFBhcmFtZXRlcmkoZ2wuVEVYVFVSRV8yRCwgZ2wuVEVYVFVSRV9NQUdfRklMVEVSLCBnbC5ORUFSRVNUKTtcbiAgZ2wudGV4SW1hZ2UyRChnbC5URVhUVVJFXzJELCAwLCBnbC5SR0JBMzJJLCBkaW0ueCwgZGltLnksIDAsIGdsLlJHQkFfSU5URUdFUiwgZ2wuSU5ULCBkYXRhKTtcbiAgLy9nbC50ZXhJbWFnZTJEKGdsLlRFWFRVUkVfMkQsIDAsIGdsLlJHQkEzMkYsIHNpemUsIHNpemUsIDAsIGdsLlJHQkEsIGdsLkZMT0FULCBkYXRhKTtcbiAgLy9nbC50ZXhTdG9yYWdlMkQoZ2wuVEVYVFVSRV8yRCwgMSwgZ2wuUkdCQTMyRiwgc2l6ZSwgc2l6ZSk7XG4gIGdsLmJpbmRUZXh0dXJlKGdsLlRFWFRVUkVfMkQsIG51bGwpO1xuXG4gIHJldHVybiB0ZXh0dXJlO1xufVxuIiwiY29uc3QgSEFTSF9MRU5HVEggPSAyNDM7XG5jb25zdCBJTlRfTEVOR1RIID0gMjc7XG5jb25zdCBOT05DRV9MRU5HVEggPSBIQVNIX0xFTkdUSCAvIDM7XG5jb25zdCBUSU1FU1RBTVBfU1RBUlQgPSBOT05DRV9MRU5HVEg7XG5jb25zdCBUSU1FU1RBTVBfTE9XRVJfQk9VTkRfU1RBUlQ9IFRJTUVTVEFNUF9TVEFSVCArIElOVF9MRU5HVEg7XG5jb25zdCBUSU1FU1RBTVBfVVBQRVJfQk9VTkRfU1RBUlQgPSBUSU1FU1RBTVBfTE9XRVJfQk9VTkRfU1RBUlQgKyBJTlRfTEVOR1RIO1xuY29uc3QgTk9OQ0VfU1RBUlQgPSBIQVNIX0xFTkdUSCAtIE5PTkNFX0xFTkdUSDsgXG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICBIQVNIX0xFTkdUSCxcbiAgU1RBVEVfTEVOR1RIOiBIQVNIX0xFTkdUSCAqIDMsXG4gIFRJTUVTVEFNUF9TVEFSVCxcbiAgVElNRVNUQU1QX0xPV0VSX0JPVU5EX1NUQVJULFxuICBUSU1FU1RBTVBfVVBQRVJfQk9VTkRfU1RBUlQsXG4gIE5PTkNFX1NUQVJULFxuICBOT05DRV9MRU5HVEgsXG4gIElOVF9MRU5HVEgsXG4gIE5VTUJFUl9PRl9ST1VORFM6IDgxLFxuICBUUkFOU0FDVElPTl9MRU5HVEg6IEhBU0hfTEVOR1RIICogMzNcbn07XG4iLCJjb25zdCBDb25zdCA9IHJlcXVpcmUoJy4vY29uc3RhbnRzJyk7XG5cbi8qKlxuICoqICAgICAgQ3J5cHRvZ3JhcGhpYyByZWxhdGVkIGZ1bmN0aW9ucyB0byBJT1RBJ3MgQ3VybCAoc3BvbmdlIGZ1bmN0aW9uKVxuICoqL1xuXG5mdW5jdGlvbiBDdXJsKHN0YXRlKSB7XG4gIC8vIHRydXRoIHRhYmxlXG4gIHRoaXMudHJ1dGhUYWJsZSA9IG5ldyBJbnQ4QXJyYXkoWzEsIDAsIC0xLCAyLCAxLCAtMSwgMCwgMiwgLTEsIDEsIDBdKTtcbiAgdGhpcy5IQVNIX0xFTkdUSCA9IENvbnN0LkhBU0hfTEVOR1RIO1xuICB0aGlzLmluaXRpYWxpemUoc3RhdGUpO1xuICB0aGlzLnJlc2V0KCk7XG59XG5cbi8qKlxuICogICBJbml0aWFsaXplcyB0aGUgc3RhdGUgd2l0aCA3MjkgdHJpdHNcbiAqXG4gKiAgIEBtZXRob2QgaW5pdGlhbGl6ZVxuICoqL1xuQ3VybC5wcm90b3R5cGUuaW5pdGlhbGl6ZSA9IGZ1bmN0aW9uKHN0YXRlLCBsZW5ndGgpIHtcblxuICBpZiAoc3RhdGUpIHtcbiAgICB0aGlzLnN0YXRlID0gc3RhdGU7XG4gIH0gZWxzZSB7XG4gICAgdGhpcy5zdGF0ZSA9IG5ldyBJbnQ4QXJyYXkoQ29uc3QuU1RBVEVfTEVOR1RIKTtcbiAgfVxufVxuXG5DdXJsLnByb3RvdHlwZS5yZXNldCA9IGZ1bmN0aW9uKCkge1xuICB0aGlzLnN0YXRlLmZpbGwoMCk7XG59XG5cbi8qKlxuICogICBTcG9uZ2UgYWJzb3JiIGZ1bmN0aW9uXG4gKlxuICogICBAbWV0aG9kIGFic29yYlxuICoqL1xuQ3VybC5wcm90b3R5cGUuYWJzb3JiID0gZnVuY3Rpb24odHJpdHMsIG9mZnNldCwgbGVuZ3RoKSB7XG5cbiAgZG8ge1xuXG4gICAgdmFyIGkgPSAwO1xuICAgIHZhciBsaW1pdCA9IChsZW5ndGggPCBDb25zdC5IQVNIX0xFTkdUSCA/IGxlbmd0aCA6IENvbnN0LkhBU0hfTEVOR1RIKTtcblxuICAgIHdoaWxlIChpIDwgbGltaXQpIHtcblxuICAgICAgdGhpcy5zdGF0ZVtpKytdID0gdHJpdHNbb2Zmc2V0KytdO1xuICAgIH1cblxuICAgIHRoaXMudHJhbnNmb3JtKCk7XG5cbiAgfSB3aGlsZSAoKCBsZW5ndGggLT0gQ29uc3QuSEFTSF9MRU5HVEggKSA+IDApXG5cbn1cblxuLyoqXG4gKiAgIFNwb25nZSBzcXVlZXplIGZ1bmN0aW9uXG4gKlxuICogICBAbWV0aG9kIHNxdWVlemVcbiAqKi9cbkN1cmwucHJvdG90eXBlLnNxdWVlemUgPSBmdW5jdGlvbih0cml0cywgb2Zmc2V0LCBsZW5ndGgpIHtcblxuICBkbyB7XG5cbiAgICB2YXIgaSA9IDA7XG4gICAgdmFyIGxpbWl0ID0gKGxlbmd0aCA8IENvbnN0LkhBU0hfTEVOR1RIID8gbGVuZ3RoIDogQ29uc3QuSEFTSF9MRU5HVEgpO1xuXG4gICAgd2hpbGUgKGkgPCBsaW1pdCkge1xuXG4gICAgICB0cml0c1tvZmZzZXQrK10gPSB0aGlzLnN0YXRlW2krK107XG4gICAgfVxuXG4gICAgdGhpcy50cmFuc2Zvcm0oKTtcblxuICB9IHdoaWxlICgoIGxlbmd0aCAtPSBDb25zdC5IQVNIX0xFTkdUSCApID4gMClcbn1cblxuLyoqXG4gKiAgIFNwb25nZSB0cmFuc2Zvcm0gZnVuY3Rpb25cbiAqXG4gKiAgIEBtZXRob2QgdHJhbnNmb3JtXG4gKiovXG5DdXJsLnByb3RvdHlwZS50cmFuc2Zvcm0gPSBmdW5jdGlvbigpIHtcblxuICB2YXIgc3RhdGVDb3B5ID0gW10sIGluZGV4ID0gMDtcblxuICBmb3IgKHZhciByb3VuZCA9IDA7IHJvdW5kIDwgQ29uc3QuTlVNQkVSX09GX1JPVU5EUzsgcm91bmQrKykge1xuXG4gICAgc3RhdGVDb3B5ID0gdGhpcy5zdGF0ZS5zbGljZSgpO1xuXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBDb25zdC5TVEFURV9MRU5HVEg7IGkrKykge1xuXG4gICAgICB0aGlzLnN0YXRlW2ldID0gdGhpcy50cnV0aFRhYmxlW3N0YXRlQ29weVtpbmRleF0gKyAoc3RhdGVDb3B5W2luZGV4ICs9IChpbmRleCA8IDM2NSA/IDM2NCA6IC0zNjUpXSA8PDIpICsgNV07XG4gICAgfVxuICB9XG59XG5cbm1vZHVsZS5leHBvcnRzID0gQ3VybDtcbiIsImNvbnN0IFBlYXJsRGl2ZXIgPSByZXF1aXJlKCcuL3BlYXJsZGl2ZXInKTtcbmNvbnN0IEN1cmwgPSByZXF1aXJlKFwiLi9jdXJsXCIpO1xuY29uc3QgQ29uc3QgPSByZXF1aXJlKCcuL2NvbnN0YW50cycpO1xuY29uc3QgQ29udmVydGVyID0gcmVxdWlyZSgnaW90YS5jcnlwdG8uanMnKS5jb252ZXJ0ZXI7XG5jb25zdCBOT05DRV9USU1FU1RBTVBfTE9XRVJfQk9VTkQgPSAwO1xuY29uc3QgTk9OQ0VfVElNRVNUQU1QX1VQUEVSX0JPVU5EID0gQ29udmVydGVyLmZyb21WYWx1ZSgweGZmZmZmZmZmZmZmZmZmZmYpO1xuY29uc3QgTUFYX1RJTUVTVEFNUF9WQUxVRSA9IChNYXRoLnBvdygzLDI3KSAtIDEpIC8gMiBcblxubGV0IHBkSW5zdGFuY2U7XG5cbmNvbnN0IHBvdyA9IChvcHRpb25zLCBzdWNjZXNzLCBlcnJvcikgPT4geyAgXG4gIGxldCBzdGF0ZTtcblxuICBpZiAoJ3RyeXRlcycgaW4gb3B0aW9ucykge1xuICAgIHN0YXRlID0gUGVhcmxEaXZlci5wcmVwYXJlKG9wdGlvbnMudHJ5dGVzKTtcbiAgfSBlbHNlIGlmICgnc3RhdGUnIGluIG9wdGlvbnMpIHtcbiAgICBzdGF0ZSA9IFBlYXJsRGl2ZXIub2Zmc2V0U3RhdGUob3B0aW9ucy5zdGF0ZSk7XG4gIH0gZWxzZSB7XG4gICAgZXJyb3IoXCJFcnJvcjogbm8gdHJ5dGVzIG9yIHN0YXRlIG1hdHJpeCBwcm92aWRlZFwiKTtcbiAgfVxuICBsZXQgcG93UHJvbWlzZSA9IFBlYXJsRGl2ZXIuc2VhcmNoKHBkSW5zdGFuY2UsIHN0YXRlLCBvcHRpb25zLm1pbldlaWdodClcbiAgaWYodHlwZW9mIHN1Y2Nlc3MgPT09ICdmdW5jdGlvbicpIHtcbiAgICBwb3dQcm9taXNlLnRoZW4oc3VjY2VzcykuY2F0Y2goZXJyb3IpXG4gIH1cbiAgcmV0dXJuIHBvd1Byb21pc2U7XG59O1xuXG5jb25zdCBUQUdfVFJJTkFSWV9TVEFSVCA9IDIyOTU7XG5jb25zdCBUQUdfVFJJTkFSWV9TSVpFID0gMjc7XG5cbmNvbnN0IHNldFRpbWVzdGFtcCA9IChzdGF0ZSkgPT4ge1xuICBjb25zdCB0aW1lc3RhbXAgPSBzdGF0ZS5zdWJhcnJheShDb25zdC5USU1FU1RBTVBfU1RBUlQsIENvbnN0LlRJTUVTVEFNUF9MT1dFUl9CT1VORF9TVEFSVCk7XG4gIGNvbnN0IHVwcGVyID0gc3RhdGUuc3ViYXJyYXkoQ29uc3QuVElNRVNUQU1QX1VQUEVSX0JPVU5EX1NUQVJULCBDb25zdC5OT05DRV9TVEFSVCk7XG4gIHRpbWVzdGFtcC5maWxsKDApO1xuICBDb252ZXJ0ZXIuZnJvbVZhbHVlKERhdGUubm93KCkpLm1hcCgodiwgaSkgPT4gdGltZXN0YW1wW2ldID0gdik7XG4gIHN0YXRlLnN1YmFycmF5KENvbnN0LlRJTUVTVEFNUF9MT1dFUl9CT1VORF9TVEFSVCwgQ29uc3QuVElNRVNUQU1QX1VQUEVSX0JPVU5EX1NUQVJUKS5maWxsKDApO1xuICB1cHBlci5maWxsKDApO1xuICBOT05DRV9USU1FU1RBTVBfVVBQRVJfQk9VTkQubWFwKCh2LGkpID0+IHVwcGVyW2ldID0gdik7XG59XG5cbmNvbnN0IG92ZXJyaWRlQXR0YWNoVG9UYW5nbGUgPSBpb3RhID0+IHtcbiAgaW90YS5hcGkuYXR0YWNoVG9UYW5nbGUgPSAoXG4gICAgdHJ1bmtUcmFuc2FjdGlvbixcbiAgICBicmFuY2hUcmFuc2FjdGlvbixcbiAgICBtaW5XZWlnaHQsXG4gICAgdHJ5dGVzLFxuICAgIGNhbGxiYWNrXG4gICkgPT4ge1xuICBjb25zdCBjY3VybEhhc2hpbmcgPSBmdW5jdGlvbih0cnVua1RyYW5zYWN0aW9uLCBicmFuY2hUcmFuc2FjdGlvbiwgbWluV2VpZ2h0LCB0cnl0ZXMsIGNhbGxiYWNrKSB7XG4gICAgY29uc3QgaW90YU9iaiA9IGlvdGFcblxuICAgIC8vIGlucHV0VmFsaWRhdG9yOiBDaGVjayBpZiBjb3JyZWN0IGhhc2hcbiAgICBpZiAoIWlvdGFPYmoudmFsaWQuaXNIYXNoKHRydW5rVHJhbnNhY3Rpb24pKSB7XG4gICAgICByZXR1cm4gY2FsbGJhY2sobmV3IEVycm9yKFwiSW52YWxpZCB0cnVua1RyYW5zYWN0aW9uXCIpKVxuICAgIH1cblxuICAgIC8vIGlucHV0VmFsaWRhdG9yOiBDaGVjayBpZiBjb3JyZWN0IGhhc2hcbiAgICBpZiAoIWlvdGFPYmoudmFsaWQuaXNIYXNoKGJyYW5jaFRyYW5zYWN0aW9uKSkge1xuICAgICAgcmV0dXJuIGNhbGxiYWNrKG5ldyBFcnJvcihcIkludmFsaWQgYnJhbmNoVHJhbnNhY3Rpb25cIikpXG4gICAgfVxuXG4gICAgLy8gaW5wdXRWYWxpZGF0b3I6IENoZWNrIGlmIGludFxuICAgIGlmICghaW90YU9iai52YWxpZC5pc1ZhbHVlKG1pbldlaWdodCkpIHtcbiAgICAgIHJldHVybiBjYWxsYmFjayhuZXcgRXJyb3IoXCJJbnZhbGlkIG1pbldlaWdodE1hZ25pdHVkZVwiKSlcbiAgICB9XG5cbiAgICB2YXIgZmluYWxCdW5kbGVUcnl0ZXMgPSBbXVxuICAgIHZhciBwcmV2aW91c1R4SGFzaFxuICAgIHZhciBpID0gMFxuXG4gICAgZnVuY3Rpb24gbG9vcFRyeXRlcygpIHtcbiAgICAgIGdldEJ1bmRsZVRyeXRlcyh0cnl0ZXNbaV0sIGZ1bmN0aW9uKGVycm9yKSB7XG4gICAgICAgIGlmIChlcnJvcikge1xuICAgICAgICAgIHJldHVybiBjYWxsYmFjayhlcnJvcilcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBpKytcbiAgICAgICAgICBpZiAoaSA8IHRyeXRlcy5sZW5ndGgpIHtcbiAgICAgICAgICAgIGxvb3BUcnl0ZXMoKVxuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAvLyByZXZlcnNlIHRoZSBvcmRlciBzbyB0aGF0IGl0J3MgYXNjZW5kaW5nIGZyb20gY3VycmVudEluZGV4XG4gICAgICAgICAgICByZXR1cm4gY2FsbGJhY2sobnVsbCwgZmluYWxCdW5kbGVUcnl0ZXMucmV2ZXJzZSgpKVxuICAgICAgICAgIH1cbiAgICAgICAgfVxuICAgICAgfSlcbiAgICB9XG5cbiAgICBmdW5jdGlvbiBnZXRCdW5kbGVUcnl0ZXModGhpc1RyeXRlcywgY2FsbGJhY2spIHtcbiAgICAgIC8vIFBST0NFU1MgTE9HSUM6XG4gICAgICAvLyBTdGFydCB3aXRoIGxhc3QgaW5kZXggdHJhbnNhY3Rpb25cbiAgICAgIC8vIEFzc2lnbiBpdCB0aGUgdHJ1bmsgLyBicmFuY2ggd2hpY2ggdGhlIHVzZXIgaGFzIHN1cHBsaWVkXG4gICAgICAvLyBJRiB0aGVyZSBpcyBhIGJ1bmRsZSwgY2hhaW4gIHRoZSBidW5kbGUgdHJhbnNhY3Rpb25zIHZpYVxuICAgICAgLy8gdHJ1bmtUcmFuc2FjdGlvbiB0b2dldGhlclxuXG4gICAgICB2YXIgdHhPYmplY3QgPSBpb3RhT2JqLnV0aWxzLnRyYW5zYWN0aW9uT2JqZWN0KHRoaXNUcnl0ZXMpXG4gICAgICB0eE9iamVjdC50YWcgPSB0eE9iamVjdC5vYnNvbGV0ZVRhZ1xuICAgICAgdHhPYmplY3QuYXR0YWNobWVudFRpbWVzdGFtcCA9IERhdGUubm93KClcbiAgICAgIHR4T2JqZWN0LmF0dGFjaG1lbnRUaW1lc3RhbXBMb3dlckJvdW5kID0gMFxuICAgICAgdHhPYmplY3QuYXR0YWNobWVudFRpbWVzdGFtcFVwcGVyQm91bmQgPSBNQVhfVElNRVNUQU1QX1ZBTFVFXG4gICAgICAvLyBJZiB0aGlzIGlzIHRoZSBmaXJzdCB0cmFuc2FjdGlvbiwgdG8gYmUgcHJvY2Vzc2VkXG4gICAgICAvLyBNYWtlIHN1cmUgdGhhdCBpdCdzIHRoZSBsYXN0IGluIHRoZSBidW5kbGUgYW5kIHRoZW5cbiAgICAgIC8vIGFzc2lnbiBpdCB0aGUgc3VwcGxpZWQgdHJ1bmsgYW5kIGJyYW5jaCB0cmFuc2FjdGlvbnNcbiAgICAgIGlmICghcHJldmlvdXNUeEhhc2gpIHtcbiAgICAgICAgLy8gQ2hlY2sgaWYgbGFzdCB0cmFuc2FjdGlvbiBpbiB0aGUgYnVuZGxlXG4gICAgICAgIGlmICh0eE9iamVjdC5sYXN0SW5kZXggIT09IHR4T2JqZWN0LmN1cnJlbnRJbmRleCkge1xuICAgICAgICAgIHJldHVybiBjYWxsYmFjayhcbiAgICAgICAgICAgIG5ldyBFcnJvcihcbiAgICAgICAgICAgICAgXCJXcm9uZyBidW5kbGUgb3JkZXIuIFRoZSBidW5kbGUgc2hvdWxkIGJlIG9yZGVyZWQgaW4gZGVzY2VuZGluZyBvcmRlciBmcm9tIGN1cnJlbnRJbmRleFwiXG4gICAgICAgICAgICApXG4gICAgICAgICAgKVxuICAgICAgICB9XG5cbiAgICAgICAgdHhPYmplY3QudHJ1bmtUcmFuc2FjdGlvbiA9IHRydW5rVHJhbnNhY3Rpb25cbiAgICAgICAgdHhPYmplY3QuYnJhbmNoVHJhbnNhY3Rpb24gPSBicmFuY2hUcmFuc2FjdGlvblxuICAgICAgfSBlbHNlIHtcbiAgICAgICAgLy8gQ2hhaW4gdGhlIGJ1bmRsZSB0b2dldGhlciB2aWEgdGhlIHRydW5rVHJhbnNhY3Rpb24gKHByZXZpb3VzIHR4IGluIHRoZSBidW5kbGUpXG4gICAgICAgIC8vIEFzc2lnbiB0aGUgc3VwcGxpZWQgdHJ1bmtUcmFuc2FjaXRvbiBhcyBicmFuY2hUcmFuc2FjdGlvblxuICAgICAgICB0eE9iamVjdC50cnVua1RyYW5zYWN0aW9uID0gcHJldmlvdXNUeEhhc2hcbiAgICAgICAgdHhPYmplY3QuYnJhbmNoVHJhbnNhY3Rpb24gPSB0cnVua1RyYW5zYWN0aW9uXG4gICAgICB9XG5cbiAgICAgIHZhciBuZXdUcnl0ZXMgPSBpb3RhT2JqLnV0aWxzLnRyYW5zYWN0aW9uVHJ5dGVzKHR4T2JqZWN0KVxuXG4gICAgICBjdXJsXG4gICAgICAgIC5wb3coeyB0cnl0ZXM6IG5ld1RyeXRlcywgbWluV2VpZ2h0OiBtaW5XZWlnaHQgfSlcbiAgICAgICAgLnRoZW4oZnVuY3Rpb24obm9uY2UpIHtcbiAgICAgICAgICB2YXIgcmV0dXJuZWRUcnl0ZXMgPSBuZXdUcnl0ZXMuc3Vic3RyKDAsIDI2NzMgLSA4MSkuY29uY2F0KG5vbmNlKVxuICAgICAgICAgIHZhciBuZXdUeE9iamVjdCA9IGlvdGFPYmoudXRpbHMudHJhbnNhY3Rpb25PYmplY3QocmV0dXJuZWRUcnl0ZXMpXG5cbiAgICAgICAgICAvLyBBc3NpZ24gdGhlIHByZXZpb3VzVHhIYXNoIHRvIHRoaXMgdHhcbiAgICAgICAgICB2YXIgdHhIYXNoID0gbmV3VHhPYmplY3QuaGFzaFxuICAgICAgICAgIHByZXZpb3VzVHhIYXNoID0gdHhIYXNoXG5cbiAgICAgICAgICBmaW5hbEJ1bmRsZVRyeXRlcy5wdXNoKHJldHVybmVkVHJ5dGVzKVxuICAgICAgICAgIGNhbGxiYWNrKG51bGwpXG4gICAgICAgIH0pXG4gICAgICAgIC5jYXRjaChjYWxsYmFjaylcbiAgICB9XG4gICAgbG9vcFRyeXRlcygpXG4gIH1cbiAgY2N1cmxIYXNoaW5nKHRydW5rVHJhbnNhY3Rpb24sIGJyYW5jaFRyYW5zYWN0aW9uLCBtaW5XZWlnaHQsIHRyeXRlcywgZnVuY3Rpb24oZXJyb3IsIHN1Y2Nlc3MpIHtcbiAgICBpZiAoZXJyb3IpIHtcbiAgICAgICAgY29uc29sZS5sb2coZXJyb3IpO1xuICAgIH0gZWxzZSB7XG4gICAgICAgIGNvbnNvbGUubG9nKHN1Y2Nlc3MpO1xuICAgIH1cbiAgICBpZiAoY2FsbGJhY2spIHtcbiAgICAgICAgcmV0dXJuIGNhbGxiYWNrKGVycm9yLCBzdWNjZXNzKTtcbiAgICB9IGVsc2Uge1xuICAgICAgICByZXR1cm4gc3VjY2VzcztcbiAgICB9XG4gIH0pXG4gIH1cbn1cblxud2luZG93LmN1cmwgPSBtb2R1bGUuZXhwb3J0cyA9IHtcbiAgaW5pdDogKCkgPT4geyBcbiAgICBwZEluc3RhbmNlID0gUGVhcmxEaXZlci5pbnN0YW5jZSgpOyBcbiAgICBpZihwZEluc3RhbmNlID09IG51bGwpIHtcbiAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9XG4gICAgcmV0dXJuIHRydWU7XG4gIH0sXG4gIHBvdyxcbiAgcHJlcGFyZTogUGVhcmxEaXZlci5wcmVwYXJlLFxuICBzZXRPZmZzZXQ6IChvKSA9PiB7cGRJbnN0YW5jZS5vZmZzZXQgPSBvfSxcbiAgaW50ZXJydXB0OiAoKSA9PiBpbnRlcnJ1cHQocGRJbnN0YW5jZSksXG4gIHJlc3VtZTogKCkgPT4gUGVhcmxEaXZlci5kb05leHQocGRJbnN0YW5jZSksXG4gIHJlbW92ZTogKCkgPT4gcGRJbnN0YW5jZS5xdWV1ZS51bnNoaWZ0KCksXG4gIC8vZ2V0SGFzaFJvd3M6IChjKSA9PiBjKFBlYXJsRGl2ZXIuZ2V0SGFzaENvdW50KCkpLFxuICBvdmVycmlkZUF0dGFjaFRvVGFuZ2xlXG59XG4iLCJjb25zdCBDb252ZXJ0ZXIgPSByZXF1aXJlKCdpb3RhLmNyeXB0by5qcycpLmNvbnZlcnRlcjtcbmNvbnN0IEN1cmwgPSByZXF1aXJlKFwiLi9jdXJsXCIpO1xuY29uc3QgV2ViR0wgPSByZXF1aXJlKCcuL1dlYkdMJyk7XG5jb25zdCBTZWFyY2hJbml0ID0gcmVxdWlyZSgnLi9zZWFyY2hJbml0Jyk7XG5jb25zdCBLUk5MID0gcmVxdWlyZSgnLi9zaGFkZXJzJyk7XG5jb25zdCBDb25zdCA9IHJlcXVpcmUoJy4vY29uc3RhbnRzJyk7XG5cbmNvbnN0IFRFWEVMU0laRSA9IDQ7XG5cbmNvbnN0IFBEU3RhdGUgPSB7XG4gIFJFQURZOiAwLFxuICBTRUFSQ0hJTkc6IDEsXG4gIElOVEVSUlVQVEVEOiAtMSxcbn07XG5cbmNvbnN0IHBhY2sgPSAobCkgPT4gKHIsayxpKSA9PiAoaSVsID09PTAgPyByLnB1c2goW2tdKTogcltyLmxlbmd0aC0xXS5wdXNoKGspKSAmJiByO1xuXG5jb25zdCBwZWFybERpdmVyQ2FsbGJhY2sgPSAocmVzLCB0cmFuc2FjdGlvblRyaXRzLCBtaW5XZWlnaHRNYWduaXR1ZGUsIG1fc2VsZikgPT4gXG57XG4gIHJldHVybiAobm9uY2UsIHNlYXJjaE9iamVjdCkgPT4ge1xuICAgIHJlcyhDb252ZXJ0ZXIudHJ5dGVzKG5vbmNlKSk7XG4gIH1cbn1cblxuY29uc3QgUGVhcmxEaXZlckluc3RhbmNlID0gKG9mZnNldCkgPT4ge1xuICBpZihXZWJHTCkge1xuICAgIGxldCBpbnN0YW5jZSA9IG5ldyBPYmplY3QoKTtcbiAgICBpbnN0YW5jZS5jb250ZXh0ID0gV2ViR0wud29ya2VyKENvbnN0LlNUQVRFX0xFTkdUSCsxLCBURVhFTFNJWkUpO1xuICAgIGluc3RhbmNlLm9mZnNldCA9IGluc3RhbmNlLmNvbnRleHQuZGltLnkgKiAob2Zmc2V0IHx8IDApO1xuICAgIGluc3RhbmNlLmJ1ZiA9IGluc3RhbmNlLmNvbnRleHQuaXB0LmRhdGE7XG4gICAgV2ViR0wuYWRkUHJvZ3JhbShpbnN0YW5jZS5jb250ZXh0LCBcImluaXRcIiwgS1JOTC5pbml0LCBcImdyX29mZnNldFwiKTtcbiAgICBXZWJHTC5hZGRQcm9ncmFtKGluc3RhbmNlLmNvbnRleHQsIFwiaW5jcmVtZW50XCIsIEtSTkwuaW5jcmVtZW50KTtcbiAgICBXZWJHTC5hZGRQcm9ncmFtKGluc3RhbmNlLmNvbnRleHQsIFwidHdpc3RcIiwgS1JOTC50cmFuc2Zvcm0pO1xuICAgIFdlYkdMLmFkZFByb2dyYW0oaW5zdGFuY2UuY29udGV4dCwgXCJjaGVja1wiLCBLUk5MLmNoZWNrLCBcIm1pbldlaWdodE1hZ25pdHVkZVwiKTtcbiAgICBXZWJHTC5hZGRQcm9ncmFtKGluc3RhbmNlLmNvbnRleHQsIFwiY29sX2NoZWNrXCIsIEtSTkwuY29sX2NoZWNrKTtcbiAgICBXZWJHTC5hZGRQcm9ncmFtKGluc3RhbmNlLmNvbnRleHQsIFwiZmluYWxpemVcIiwgS1JOTC5maW5hbGl6ZSk7XG4gICAgaW5zdGFuY2Uuc3RhdGUgPSBQRFN0YXRlLlJFQURZO1xuICAgIGluc3RhbmNlLnF1ZXVlID0gW107XG4gICAgcmV0dXJuIGluc3RhbmNlO1xuICB9XG59XG5cbmNvbnN0IHNlYXJjaCA9IChpbnN0YW5jZSwgc3RhdGVzLCBtaW5XZWlnaHQpID0+e1xuICBpZighaW5zdGFuY2UuY29udGV4dCkge1xuICAgIFByb21pc2UucmVqZWN0KG5ldyBFcnJvcihcIldlYmdsMiBJcyBub3QgQXZhaWxhYmxlXCIpKTtcbiAgfSBlbHNlIGlmIChtaW5XZWlnaHQgPj0gQ29uc3QuSEFTSF9MRU5HVEggfHwgbWluV2VpZ2h0IDw9IDApIHtcbiAgICBQcm9taXNlLnJlamVjdChuZXcgRXJyb3IoXCJCYWQgTWluLVdlaWdodCBNYWduaXR1ZGVcIikpO1xuICB9XG4gIHJldHVybiBuZXcgUHJvbWlzZSgocmVzLCByZWopID0+IHtcbiAgICBpbnN0YW5jZS5xdWV1ZS5wdXNoKHtcbiAgICAgIHN0YXRlczogc3RhdGVzLCBcbiAgICAgIG13bTogbWluV2VpZ2h0LCBcbiAgICAgIGNhbGw6IHBlYXJsRGl2ZXJDYWxsYmFjayhyZXMsIHN0YXRlcywgbWluV2VpZ2h0LCBpbnN0YW5jZSlcbiAgICB9KTtcbiAgICBpZihpbnN0YW5jZS5zdGF0ZSA9PSBQRFN0YXRlLlJFQURZKSBkb05leHQoaW5zdGFuY2UpO1xuICB9KTtcbn1cblxuY29uc3QgaW50ZXJydXB0ID0gKGluc3RhbmNlKSA9PiB7XG4gIGlmKGluc3RhbmNlLnN0YXRlID09IFBEU3RhdGUuU0VBUkNISU5HKSBpbnN0YW5jZS5zdGF0ZSA9IFBEU3RhdGUuSU5URVJSVVBURUQ7XG59XG5cbmNvbnN0IGRvTmV4dCA9IChpbnN0YW5jZSkgPT4ge1xuICB2YXIgbmV4dCA9IGluc3RhbmNlLnF1ZXVlLnNoaWZ0KCk7XG4gIGlmKGluc3RhbmNlLnN0YXRlICE9IFBEU3RhdGUuU0VBUkNISU5HKSB7XG4gICAgaWYobmV4dCAhPSBudWxsKSB7XG4gICAgICBpbnN0YW5jZS5zdGF0ZSA9IFBEU3RhdGUuU0VBUkNISU5HO1xuICAgICAgX1dlYkdMRmluZE5vbmNlKGluc3RhbmNlLCBuZXh0KTtcbiAgICB9IFxuICB9IGVsc2Uge1xuICAgIGluc3RhbmNlLnN0YXRlID0gUERTdGF0ZS5SRUFEWTtcbiAgfVxufVxuXG5jb25zdCBfc2F2ZSA9IChpbnN0YW5jZSwgc2VhcmNoT2JqZWN0KSA9PiB7XG4gIGluc3RhbmNlLmJ1Zi5yZWR1Y2UocGFjayg0KSwgW10pLnNsaWNlKDAsQ29uc3QuU1RBVEVfTEVOR1RIKVxuICAgIC5yZWR1Y2UoKGEsdik9PiBhLm1hcCgoYyxpKSA9PiBjLnB1c2godltpXSkpJiYgYSwgW1tdLFtdXSlcbiAgICAucmVkdWNlKChhLHYsaSkgPT4gKGklMiA/IGEuc2V0KFwiaGlnaFwiLCB2KSA6IGEuc2V0KFwibG93XCIsIHYpKSAmJiBhLCBuZXcgTWFwKCkpXG4gICAgLmZvckVhY2goKHYsaykgPT4gc2VhcmNoT2JqZWN0LnN0YXRlc1trXSA9IHYpO1xuICBpbnN0YW5jZS5xdWV1ZS51bnNoaWZ0KHNlYXJjaE9iamVjdCk7XG59XG5cbmNvbnN0IF9XZWJHTFdyaXRlQnVmZmVycyA9IChpbnN0YW5jZSwgc3RhdGVzKSA9PiB7XG4gIGZvcih2YXIgaSA9IDA7IGkgPCBDb25zdC5TVEFURV9MRU5HVEg7IGkrKykge1xuICAgIGluc3RhbmNlLmJ1ZltpICogVEVYRUxTSVpFXSA9IHN0YXRlcy5sb3dbaV07XG4gICAgaW5zdGFuY2UuYnVmW2kgKiBURVhFTFNJWkUgKyAxXSA9IHN0YXRlcy5oaWdoW2ldO1xuICAgIGluc3RhbmNlLmJ1ZltpICogVEVYRUxTSVpFICsgMl0gPSBzdGF0ZXMubG93W2ldO1xuICAgIGluc3RhbmNlLmJ1ZltpICogVEVYRUxTSVpFICsgM10gPSBzdGF0ZXMuaGlnaFtpXTtcbiAgfVxufVxuXG5cbmNvbnN0IF9XZWJHTFNlYXJjaCA9IChpbnN0YW5jZSwgc2VhcmNoT2JqZWN0KSA9PiB7XG4gIFdlYkdMLnJ1bihpbnN0YW5jZS5jb250ZXh0LCBcImluY3JlbWVudFwiKTtcbiAgV2ViR0wucnVuKGluc3RhbmNlLmNvbnRleHQsIFwidHdpc3RcIiwgQ29uc3QuTlVNQkVSX09GX1JPVU5EUyk7XG4gIFdlYkdMLnJ1bihpbnN0YW5jZS5jb250ZXh0LCBcImNoZWNrXCIsIDEsIHtuOlwibWluV2VpZ2h0TWFnbml0dWRlXCIsIHY6IHNlYXJjaE9iamVjdC5td219KTtcbiAgV2ViR0wucnVuKGluc3RhbmNlLmNvbnRleHQsIFwiY29sX2NoZWNrXCIpO1xuXG4gIGlmKFdlYkdMLnJlYWREYXRhKGluc3RhbmNlLmNvbnRleHQsIENvbnN0LlNUQVRFX0xFTkdUSCwwLCAxLCAxKVsyXSA9PT0gLTEgKSB7XG4gICAgaWYoaW5zdGFuY2Uuc3RhdGUgPT0gUERTdGF0ZS5JTlRFUlJVUFRFRCkgcmV0dXJuIGluc3RhbmNlLl9zYXZlKHNlYXJjaE9iamVjdCk7XG4gICAgLy9yZXF1ZXN0QW5pbWF0aW9uRnJhbWUoKCkgPT4gaW5zdGFuY2UuX1dlYkdMU2VhcmNoKHNlYXJjaE9iamVjdCkpO1xuICAgIHNldFRpbWVvdXQoKCkgPT4gX1dlYkdMU2VhcmNoKGluc3RhbmNlLCBzZWFyY2hPYmplY3QpLCAxKTtcbiAgfSBlbHNlIHtcbiAgICBXZWJHTC5ydW4oaW5zdGFuY2UuY29udGV4dCwgXCJmaW5hbGl6ZVwiKTtcbiAgICBzZWFyY2hPYmplY3QuY2FsbChcbiAgICAgIFdlYkdMLnJlYWREYXRhKGluc3RhbmNlLmNvbnRleHQsIDAsMCxpbnN0YW5jZS5jb250ZXh0LmRpbS54LDEpXG4gICAgICAucmVkdWNlKHBhY2soNCksIFtdKVxuICAgICAgLnNsaWNlKDAsIENvbnN0LkhBU0hfTEVOR1RIKVxuICAgICAgLm1hcCh4ID0+IHhbM10pLCBcbiAgICAgIHNlYXJjaE9iamVjdCk7XG4gICAgZG9OZXh0KGluc3RhbmNlKTtcbiAgfVxufVxuXG5jb25zdCBfV2ViR0xGaW5kTm9uY2UgPSAoaW5zdGFuY2UsIHNlYXJjaE9iamVjdCkgPT4ge1xuICBfV2ViR0xXcml0ZUJ1ZmZlcnMoaW5zdGFuY2UsIHNlYXJjaE9iamVjdC5zdGF0ZXMpO1xuICBXZWJHTC53cml0ZURhdGEoaW5zdGFuY2UuY29udGV4dCwgaW5zdGFuY2UuYnVmKTtcbiAgV2ViR0wucnVuKGluc3RhbmNlLmNvbnRleHQsIFwiaW5pdFwiLCAxLCB7bjogXCJncl9vZmZzZXRcIiwgdjogaW5zdGFuY2Uub2Zmc2V0fSk7XG4gIC8vcmVxdWVzdEFuaW1hdGlvbkZyYW1lKCgpID0+IGluc3RhbmNlLl9XZWJHTFNlYXJjaChzZWFyY2hPYmplY3QpKTtcbiAgc2V0VGltZW91dCgoKSA9PiBfV2ViR0xTZWFyY2goaW5zdGFuY2UsIHNlYXJjaE9iamVjdCksIDEpO1xufVxuY29uc3Qgc2VhcmNoV2l0aENhbGxiYWNrID0gKGluc3RhbmNlLCB0cmFuc2FjdGlvblRyeXRlcywgbWluV2VpZ2h0TWFnbml0dWRlLCBjYWxsYmFjaywgZXJyKSA9PiB7XG4gIGlmICh0cmFuc2FjdGlvblRyaXRzLmxlbmd0aCA8IENvbnN0LlRSQU5TQUNUSU9OX0xFTkdUSCAtIENvbnN0LkhBU0hfTEVOR1RIKSByZXR1cm4gbnVsbDtcbiAgdmFyIGN1cmwgPSBuZXcgQ3VybCgpO1xuICBsZXQgdHJhbnNhY3Rpb25Ucml0cyA9IENvbnZlcnRlci50cml0cyh0cmFuc2FjdGlvblRyeXRlcyk7XG4gIGN1cmwuYWJzb3JiKHRyYW5zYWN0aW9uVHJpdHMsIDAsIENvbnN0LlRSQU5TQUNUSU9OX0xFTkdUSCAtIENvbnN0LkhBU0hfTEVOR1RIKTtcbiAgY29uc3Qgc3RhdGVzID0gU2VhcmNoSW5pdC50b1BhaXIoY3VybC5zdGF0ZSwgbWluV2VpZ2h0TWFnbml0dWRlKTtcbiAgc2VhcmNoKGluc3RhbmNlLCBzdGF0ZXMsIG1pbldlaWdodE1hZ25pdHVkZSkudGhlbihjYWxsYmFjaykuY2F0Y2goZXJyKTtcbn1cbmNvbnN0IG9mZnNldFN0YXRlID0gKHN0YXRlKSA9PiB7XG4gICAgcmV0dXJuIFNlYXJjaEluaXQudG9QYWlyKENvbnZlcnRlci50cml0cyhzdGF0ZSkpO1xufVxuY29uc3QgcHJlcGFyZSA9ICh0cmFuc2FjdGlvblRyeXRlcywgbWluV2VpZ2h0TWFnbml0dWRlKSA9PiB7XG4gIHZhciBjdXJsID0gbmV3IEN1cmwoKTtcbiAgbGV0IHRyYW5zYWN0aW9uVHJpdHMgPSBDb252ZXJ0ZXIudHJpdHModHJhbnNhY3Rpb25Ucnl0ZXMpO1xuICBjdXJsLmFic29yYih0cmFuc2FjdGlvblRyaXRzLCAwLCBDb25zdC5UUkFOU0FDVElPTl9MRU5HVEggLSBDb25zdC5IQVNIX0xFTkdUSCk7XG4gIHRyYW5zYWN0aW9uVHJpdHMuc2xpY2UoQ29uc3QuVFJBTlNBQ1RJT05fTEVOR1RIIC0gQ29uc3QuSEFTSF9MRU5HVEgsIENvbnN0LlRSQU5TQUNUSU9OX0xFTkdUSCkuZm9yRWFjaCgodixpKSA9PiB7IGN1cmwuc3RhdGVbaV0gPSB2OyB9KTtcbiAgY29uc3Qgc3RhdGVzID0gU2VhcmNoSW5pdC50b1BhaXIoY3VybC5zdGF0ZSk7XG4gIHJldHVybiBzdGF0ZXM7XG59XG5cbm1vZHVsZS5leHBvcnRzID0ge1xuICBpbnN0YW5jZTogUGVhcmxEaXZlckluc3RhbmNlLFxuICBvZmZzZXRTdGF0ZSxcbiAgcHJlcGFyZSxcbiAgc2VhcmNoLFxuICBkb05leHQsXG59O1xuIiwiY29uc3QgQ29uc3QgPSByZXF1aXJlKCcuL2NvbnN0YW50cycpXG5sZXQgXG4gIFRSWVRFX0xFTkdUSCA9IDI2NzMsXG4gIFRSQU5TQUNUSU9OX0xFTkdUSD0gVFJZVEVfTEVOR1RIICogMyxcbiAgTE9XX0JJVFM9IDAsLy8wMDAwMDAwMCxcbiAgSElHSF9CSVRTPSAtMSwvLzB4RkZGRkZGRkYsLy9GRkZGRkZGRiw0Mjk0OTY3Mjk1LCBcbiAgTE9XXzA9IDB4REI2REI2REIsLy82REI2REI2RCxcbiAgTE9XXzE9IDB4RjFGOEZDN0UsLy8zRjFGOEZDNyxcbiAgTE9XXzI9IDB4N0ZGRkUwMEYsLy9GRkZDMDFGRixcbiAgTE9XXzM9IDB4RkZDMDAwMDAsLy8wN0ZGRkZGRixcbiAgSElHSF8wPSAweEI2REI2REI2LC8vREI2REI2REIsXG4gIEhJR0hfMT0gMHg4RkM3RTNGMSwvL0Y4RkM3RTNGLFxuICBISUdIXzI9IDB4RkZDMDFGRkYsLy9GODAzRkZGRixcbiAgSElHSF8zPSAweDAwM0ZGRkZGOyAvL0ZGRkZGRkZGLFxuLypcbiAgSElHSF9CSVRTPSAweEZGRkZGRkZGRkZGRkZGRkYsXG4gIExPV19CSVRTPSAweDAwMDAwMDAwMDAwMDAwMDAsXG4gIExPV18wPSAweERCNkRCNkRCNkRCNkRCNkQsXG4gIEhJR0hfMD0gMHhCNkRCNkRCNkRCNkRCNkRCLFxuICBMT1dfMT0gMHhGMUY4RkM3RTNGMUY4RkM3LFxuICBISUdIXzE9IDB4OEZDN0UzRjFGOEZDN0UzRixcbiAgTE9XXzI9IDB4N0ZGRkUwMEZGRkZDMDFGRixcbiAgSElHSF8yPSAweEZGQzAxRkZGRjgwM0ZGRkYsXG4gIExPV18zPSAweEZGQzAwMDAwMDdGRkZGRkYsXG4gIEhJR0hfMz0gMHgwMDNGRkZGRkZGRkZGRkZGO1xuICAqL1xuXG5cbmZ1bmN0aW9uIG9mZnNldChzdGF0ZXMsIG9mZnNldCkge1xuICBzdGF0ZXMubG93IFtvZmZzZXQgKyAwXSA9IExPV18wO1xuICBzdGF0ZXMubG93IFtvZmZzZXQgKyAxXSA9IExPV18xO1xuICBzdGF0ZXMubG93IFtvZmZzZXQgKyAyXSA9IExPV18yO1xuICBzdGF0ZXMubG93IFtvZmZzZXQgKyAzXSA9IExPV18zO1xuICBzdGF0ZXMuaGlnaFtvZmZzZXQgKyAwXSA9IEhJR0hfMDtcbiAgc3RhdGVzLmhpZ2hbb2Zmc2V0ICsgMV0gPSBISUdIXzE7XG4gIHN0YXRlcy5oaWdoW29mZnNldCArIDJdID0gSElHSF8yO1xuICBzdGF0ZXMuaGlnaFtvZmZzZXQgKyAzXSA9IEhJR0hfMztcbn1cblxuZnVuY3Rpb24gdG9QYWlyKHN0YXRlKSB7XG4gIGNvbnN0IHN0YXRlcyA9IHtcbiAgICBsb3cgOiBuZXcgSW50MzJBcnJheShDb25zdC5TVEFURV9MRU5HVEgpLFxuICAgIGhpZ2ggOiBuZXcgSW50MzJBcnJheShDb25zdC5TVEFURV9MRU5HVEgpXG4gIH1cbiAgc3RhdGUuZm9yRWFjaCgodHJpdCwgaSkgPT4ge1xuICAgIHN3aXRjaCAodHJpdCkge1xuICAgICAgY2FzZSAwOiB7XG4gICAgICAgIHN0YXRlcy5sb3dbaV0gPSBISUdIX0JJVFM7XG4gICAgICAgIHN0YXRlcy5oaWdoW2ldID0gSElHSF9CSVRTO1xuICAgICAgfSBicmVhaztcbiAgICAgIGNhc2UgMToge1xuICAgICAgICBzdGF0ZXMubG93W2ldID0gTE9XX0JJVFM7XG4gICAgICAgIHN0YXRlcy5oaWdoW2ldID0gSElHSF9CSVRTO1xuICAgICAgfSBicmVhaztcbiAgICAgIGRlZmF1bHQ6IHtcbiAgICAgICAgc3RhdGVzLmxvd1tpXSA9IEhJR0hfQklUUztcbiAgICAgICAgc3RhdGVzLmhpZ2hbaV0gPSBMT1dfQklUUztcbiAgICAgIH1cbiAgICB9XG4gIH0pO1xuICBvZmZzZXQoc3RhdGVzLCBDb25zdC5OT05DRV9TVEFSVCk7XG4gIHJldHVybiBzdGF0ZXM7XG59XG5cbmZ1bmN0aW9uIHRyYW5zZm9ybShzdGF0ZXMpIHtcbiAgdmFyIHNjcmF0Y2hwYWRIaWdoLCBzY3JhdGNocGFkTG93XG4gIHZhciBzY3JhdGNocGFkSW5kZXggPSAwLCByb3VuZCwgc3RhdGVJbmRleDtcbiAgdmFyIGFscGhhLCBiZXRhLCBnYW1tYSwgZGVsdGE7XG5cbiAgZm9yIChyb3VuZCA9IENvbnN0Lk5VTUJFUl9PRl9ST1VORFM7IHJvdW5kLS0gPiAwOyApIHtcbiAgICBzY3JhdGNocGFkTG93ID0gc3RhdGVzLmxvdy5zbGljZSgpO1xuICAgIHNjcmF0Y2hwYWRIaWdoID0gc3RhdGVzLmhpZ2guc2xpY2UoKTtcblxuICAgIGZvciAoc3RhdGVJbmRleCA9IDA7IHN0YXRlSW5kZXggPCBDb25zdC5TVEFURV9MRU5HVEg7IHN0YXRlSW5kZXgrKykge1xuICAgICAgYWxwaGEgPSBzY3JhdGNocGFkTG93W3NjcmF0Y2hwYWRJbmRleF07XG4gICAgICBiZXRhID0gc2NyYXRjaHBhZEhpZ2hbc2NyYXRjaHBhZEluZGV4XTtcbiAgICAgIGdhbW1hID0gc2NyYXRjaHBhZEhpZ2hbc2NyYXRjaHBhZEluZGV4ICs9IChzY3JhdGNocGFkSW5kZXggPCAzNjUgPyAzNjQgOiAtMzY1KV07XG4gICAgICBkZWx0YSA9IChhbHBoYSB8ICh+Z2FtbWEpKSAmIChzY3JhdGNocGFkTG93W3NjcmF0Y2hwYWRJbmRleF0gXiBiZXRhKTtcblxuICAgICAgc3RhdGVzLmxvd1tzdGF0ZUluZGV4XSA9IH5kZWx0YTtcbiAgICAgIHN0YXRlcy5oaWdoW3N0YXRlSW5kZXhdID0gKGFscGhhIF4gZ2FtbWEpIHwgZGVsdGE7XG4gICAgfVxuICB9XG59XG5cbm1vZHVsZS5leHBvcnRzID0geyB0b1BhaXIsIHRyYW5zZm9ybSB9O1xuLypcbmV4cG9ydCBkZWZhdWx0IGZ1bmN0aW9uIChzdGF0ZXMsIHRyYW5zYWN0aW9uVHJpdHMpIHtcbiAgdmFyIGksIG9mZnNldCA9IDA7XG4gIHZhciBqO1xuICAvL2ZvciAoaSA9IEhBU0hfTEVOR1RIOyBpIDwgU1RBVEVfTEVOR1RIOyBpKyspIHtcbiAgZm9yIChpID0gMDsgaSA8IENvbnN0LlNUQVRFX0xFTkdUSDsgaSsrKSB7XG4gICAgaWYgKGkgPj0gQ29uc3QuSEFTSF9MRU5HVEggJiYgaSA8IENvbnN0LlNUQVRFX0xFTkdUSCkge1xuICAgICAgc3RhdGVzLmxvd1tpXSA9IEhJR0hfQklUUztcbiAgICAgIHN0YXRlcy5oaWdoW2ldID0gSElHSF9CSVRTO1xuICAgIH0gZWxzZSB7XG4gICAgICBzdGF0ZXMubG93W2ldID0gMDtcbiAgICAgIHN0YXRlcy5oaWdoW2ldID0gMDtcbiAgICB9XG4gIH1cblxuICBmb3IgKGkgPSAoQ29uc3QuVFJBTlNBQ1RJT05fTEVOR1RIIC0gQ29uc3QuSEFTSF9MRU5HVEgpIC8gQ29uc3QuSEFTSF9MRU5HVEg7IGktLSA+IDA7ICkge1xuXG4gICAgZm9yIChqID0gMDsgaiA8IENvbnN0LkhBU0hfTEVOR1RIOyBqKyspIHtcbiAgICAgIHN3aXRjaCAodHJhbnNhY3Rpb25Ucml0c1tvZmZzZXQrK10pIHtcbiAgICAgICAgY2FzZSAwOiB7XG4gICAgICAgICAgc3RhdGVzLmxvd1tqXSA9IEhJR0hfQklUUztcbiAgICAgICAgICBzdGF0ZXMuaGlnaFtqXSA9IEhJR0hfQklUUztcbiAgICAgICAgfSBicmVhaztcbiAgICAgICAgY2FzZSAxOiB7XG4gICAgICAgICAgc3RhdGVzLmxvd1tqXSA9IExPV19CSVRTO1xuICAgICAgICAgIHN0YXRlcy5oaWdoW2pdID0gSElHSF9CSVRTO1xuICAgICAgICB9IGJyZWFrO1xuICAgICAgICBkZWZhdWx0OiB7XG4gICAgICAgICAgc3RhdGVzLmxvd1tqXSA9IEhJR0hfQklUUztcbiAgICAgICAgICBzdGF0ZXMuaGlnaFtqXSA9IExPV19CSVRTO1xuICAgICAgICB9XG4gICAgICB9XG4gICAgfVxuICAgIHRyYW5zZm9ybShzdGF0ZXMpO1xuICB9XG4gIHN0YXRlcy5sb3dbMF0gPSBMT1dfMDsgICAvLzBiMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMUw7IFxuICBzdGF0ZXMuaGlnaFswXSA9IEhJR0hfMDsgLy8wYjEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTEwMTFMO1xuICBzdGF0ZXMubG93WzFdID0gTE9XXzE7ICAgLy8wYjExMTEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTExMTEwMDAxMTFMOyBcbiAgc3RhdGVzLmhpZ2hbMV0gPSBISUdIXzE7IC8vMGIxMDAwMTExMTExMDAwMTExMTExMDAwMTExMTExMDAwMTExMTExMDAwMTExMTExMDAwMTExMTExMDAwMTExMTExTDtcbiAgc3RhdGVzLmxvd1syXSA9IExPV18yOyAgIC8vMGIwMTExMTExMTExMTExMTExMTExMDAwMDAwMDAwMTExMTExMTExMTExMTExMTExMDAwMDAwMDAwMTExMTExMTExTDsgXG4gIHN0YXRlcy5oaWdoWzJdID0gSElHSF8yOyAvLzBiMTExMTExMTExMTAwMDAwMDAwMDExMTExMTExMTExMTExMTExMTAwMDAwMDAwMDExMTExMTExMTExMTExMTExMUw7XG4gIHN0YXRlcy5sb3dbM10gPSBMT1dfMzsgICAvLzBiMTExMTExMTExMTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDExMTExMTExMTExMTExMTExMTExMTExMTExMUw7IFxuICBzdGF0ZXMuaGlnaFszXSA9IEhJR0hfMzsgLy8wYjAwMDAwMDAwMDAxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTFMO1xufVxuKi9cbiIsIm1vZHVsZS5leHBvcnRzID0gYFxuaW50IHN1bSAoaW50IGEsIGludCBiKSB7XG4gIGludCBteV9zdW0gPSBhICsgYjtcbiAgcmV0dXJuIG15X3N1bSA9PSAyID8gLTEgOiAobXlfc3VtID09IC0yKSA/IDEgOiBteV9zdW07XG59XG5pbnQgY29ucyAoaW50IGEsIGludCBiKSB7XG4gIHJldHVybiAoYSA9PSAxICYmIGIgPT0gMSk/IDEgOiAoYSA9PSAtMSAmJiBiID09IC0xKSA/IC0xIDogMDtcbn1cbmludCBhbnlfdCAoaW50IGEsIGludCBiKSB7XG4gIGludCBteV9hbnkgPSBhICsgYjtcbiAgcmV0dXJuIG15X2FueSA9PSAwID8gMCA6IChteV9hbnkgPiAwKSA/IDEgOiAtMTtcbn1cbml2ZWMyIGZ1bGxfYWRkZXIoaW50IGEsIGludCBiLCBpbnQgYykge1xuICBpbnQgY19hLCBjX2IsIHN1bV9hYiwgY19zO1xuXG4gIGNfYSAgICA9IGNvbnMoYSxiKTtcbiAgc3VtX2FiID0gc3VtKGEsYik7XG4gIGNfYiAgICA9IGNvbnMoc3VtX2FiLGMpO1xuICBjX3MgICAgPSBhbnlfdChjX2EsIGNfYik7XG5cbiAgcmV0dXJuIGl2ZWMyKHN1bShzdW1fYWIsIGMpLCBjX3MpO1xufVxuaXZlYzIgZ2V0X3N1bV90b19pbmRleChpbnQgZnJvbSwgaW50IHRvLCBpbnQgbnVtYmVyX3RvX2FkZCwgaW50IHJvdykge1xuICBpbnQgdHJpdF90b19hZGQsIHRyaXRfYXRfaW5kZXgsIHBvdywgY2FycnksIG51bV9jYXJyeTtcbiAgaXZlYzIgcmVhZF9pbiwgc3VtX291dCwgb3V0X3RyaXQ7XG4gIHBvdyA9IDE7XG4gIGNhcnJ5ID0gMDtcbiAgbnVtX2NhcnJ5ID0gMDtcblxuICBmb3IoaW50IGkgPSBmcm9tOyBpIDwgdG87IGkrKykge1xuICAgIC8vaWYodHJpdF90b19hZGQgPT0gMCAmJiBzdW1fb3V0LnQgPT0gMCkgY29udGludWU7XG5cbiAgICByZWFkX2luID0gcmVhZF9hdCAoIGl2ZWMyIChpLCByb3cpKS5yZztcblxuICAgIHRyaXRfdG9fYWRkID0gKChudW1iZXJfdG9fYWRkIC8gcG93KSAlIDMpICsgbnVtX2NhcnJ5O1xuICAgIG51bV9jYXJyeSA9IHRyaXRfdG9fYWRkID4gMSA/IDEgOiAwO1xuICAgIHRyaXRfdG9fYWRkID0gKHRyaXRfdG9fYWRkID09IDIgPyAtMSA6ICh0cml0X3RvX2FkZCA9PSAzID8gMCA6IHRyaXRfdG9fYWRkKSk7XG5cbiAgICBzdW1fb3V0ID0gZnVsbF9hZGRlcihcbiAgICAgIChyZWFkX2luLnMgPT0gTE9XX0JJVFMgPyAxIDogcmVhZF9pbi50ID09IExPV19CSVRTPyAtMSA6IDApLCBcbiAgICAgIHRyaXRfdG9fYWRkLCBcbiAgICAgIGNhcnJ5XG4gICAgKTtcblxuICAgIGlmKG15X2Nvb3JkLnggPT0gaSkgYnJlYWs7XG4gICAgY2FycnkgPSBzdW1fb3V0LnQ7XG4gICAgcG93ICo9MztcbiAgfVxuICBpZihzdW1fb3V0LnMgPT0gMCkge1xuICAgIHJldHVybiBpdmVjMihISUdIX0JJVFMpO1xuICB9IGVsc2UgaWYgKHN1bV9vdXQucyA9PSAxKSB7XG4gICAgcmV0dXJuIGl2ZWMyKExPV19CSVRTLCBISUdIX0JJVFMpO1xuICB9IGVsc2Uge1xuICAgIHJldHVybiBpdmVjMihISUdIX0JJVFMsIExPV19CSVRTKTtcbiAgfVxufVxuYFxuIiwibW9kdWxlLmV4cG9ydHMgPSBgXG4vLyBDaG9vc2UgaGlnaCAhPSAwIGlmIHlvdSB3YW50IHRvIGJhcnJpZXIgcmcgdmFsdWVzLCAwIGlmIHlvdSB3YW50IHRvIGJhcnJpZXIgYmFcbiNkZWZpbmUgV0FJVE5VTSAyXG52b2lkIGJhcnJpZXIoaXZlYzIgd2F0Y2hfY29vcmRzLCBpbnQgaGlnaCkge1xuICBpdmVjNCBteV92ZWMgPSByZWFkKCk7XG4gIGlmKHdhdGNoX2Nvb3JkcyA9PSBteV9jb29yZCkge1xuICAgIGludCBob2xkX2luZGV4ID0gMDtcbiAgICBpdmVjNCBob2xkX3RleGVsO1xuICAgIG15X3ZlYy5nID0gbXlfdmVjLmEgKyAxO1xuICAgIG15X3ZlYy5iID0gbXlfdmVjLmcgKyAxO1xuICAgIGNvbW1pdChteV92ZWMpO1xuICAgIHdoaWxlKGhvbGRfaW5kZXggPCBTVEFURV9MRU5HVEgpIHtcbiAgICAgIGhvbGRfdGV4ZWwgPSByZWFkX2F0KGl2ZWMyKGhvbGRfaW5kZXgsIG15X2Nvb3JkLnkpKTtcbiAgICAgIGlmKChoaWdoID09IDAgJiYgaG9sZF90ZXhlbC5yID09IFdBSVROVU0pIHx8KGhpZ2ggIT0gMCAmJiBob2xkX3RleGVsLmEgPT0gV0FJVE5VTSkpXG4gICAgICAgIGhvbGRfaW5kZXgrKztcbiAgICB9XG4gICAgbXlfdmVjLmEgPSBteV92ZWMuZztcbiAgICAvL215X3ZlYy5hID0gMTIzO1xuICB9IGVsc2Uge1xuICAgIGl2ZWM0IHdhdGNoID0gcmVhZF9hdCh3YXRjaF9jb29yZHMpOyAvLyByOiB2YWwgdG8gd2F0Y2gsIGc6IGV4cGVjdGVkIHZhbCwgYjogbmV4dCB2YWwgKHNob3VsZCBiZSAxKyBleHBlY3RlZCB2YWwpXG4gICAgaW50IGhvbGQgPSBoaWdoID09IDAgPyBteV92ZWMuciA6IG15X3ZlYy5hO1xuICAgIGlmKGhpZ2ggPT0gMClcbiAgICAgIG15X3ZlYy5yID0gV0FJVE5VTTtcbiAgICBlbHNlXG4gICAgICBteV92ZWMuYSA9IFdBSVROVU07XG4gICAgY29tbWl0KG15X3ZlYyk7XG4gICAgd2hpbGUod2F0Y2guZyA9PSB3YXRjaC5iIHx8IHdhdGNoLmEgIT0gd2F0Y2guZykge1xuICAgICAgLy93aGlsZSh3YXRjaC5nID09IHdhdGNoLmIgfHwgd2F0Y2guYSAhPSAxMjMpIHtcbiAgICAgIHdhdGNoID0gcmVhZF9hdCh3YXRjaF9jb29yZHMpO1xuICAgIH1cbiAgfVxuICBjb21taXQobXlfdmVjKTtcbn1cbmBcbiIsIm1vZHVsZS5leHBvcnRzID0geyBkb19jaGVjazogYFxuaW50IGNoZWNrKGludCByb3csIGludCBtaW5fd2VpZ2h0X21hZ25pdHVkZSkge1xuICBpbnQgbm9uY2VfcHJvYmUsIGk7XG4gIGl2ZWMyIHJfdGV4ZWw7XG4gIG5vbmNlX3Byb2JlID0gSElHSF9CSVRTO1xuICBmb3IoaSA9IG1pbl93ZWlnaHRfbWFnbml0dWRlOyBpLS0gPiAwOyApIHtcbiAgICByX3RleGVsID0gcmVhZF9hdChpdmVjMihIQVNIX0xFTkdUSCAtIDEgLSBpLCByb3cpKS5iYTtcbiAgICBub25jZV9wcm9iZSAmPSB+KHJfdGV4ZWwucyBeIHJfdGV4ZWwudCk7XG4gICAgaWYobm9uY2VfcHJvYmUgPT0gMCkgYnJlYWs7XG4gIH1cbiAgcmV0dXJuIG5vbmNlX3Byb2JlO1xufVxuYCwga19jaGVjazogYFxudW5pZm9ybSBpbnQgbWluV2VpZ2h0TWFnbml0dWRlO1xudm9pZCBtYWluKCkge1xuICBpbml0KCk7XG4gIGl2ZWM0IG15X3ZlYyA9IHJlYWQoKTtcbiAgaWYobXlfY29vcmQueCA9PSBTVEFURV9MRU5HVEgpIHtcbiAgICBteV92ZWMuciA9IG1pbldlaWdodE1hZ25pdHVkZTtcbiAgICBteV92ZWMuYSA9IGNoZWNrKG15X2Nvb3JkLnksIG1pbldlaWdodE1hZ25pdHVkZSk7XG4gIH1cbiAgY29tbWl0KG15X3ZlYyk7XG59XG5gLCBjb2w6IGBcbnZvaWQgbWFpbigpIHtcbiAgaW5pdCgpO1xuICBpdmVjNCBteV92ZWMgPSByZWFkKCk7XG4gIGludCBpO1xuICBpZihteV9jb29yZC54ID09IFNUQVRFX0xFTkdUSCAmJiBteV9jb29yZC55ID09IDApIHtcbiAgICBteV92ZWMuYiA9IDA7XG4gICAgaWYobXlfdmVjLmEgPT0gMCkge1xuICAgICAgaXZlYzQgcmVhZF92ZWM7XG4gICAgICBteV92ZWMuYiA9IC0xO1xuICAgICAgZm9yKGkgPSAxOyBpIDwgaW50KHNpemUueSk7IGkrKykge1xuICAgICAgICByZWFkX3ZlYyA9IHJlYWRfYXQoIGl2ZWMyKCBTVEFURV9MRU5HVEgsIGkpKTtcbiAgICAgICAgaWYocmVhZF92ZWMuYSAhPSAwKSB7XG4gICAgICAgICAgbXlfdmVjLmEgPSByZWFkX3ZlYy5hO1xuICAgICAgICAgIG15X3ZlYy5iID0gaTtcbiAgICAgICAgICBicmVhaztcbiAgICAgICAgfVxuICAgICAgfVxuICAgIH1cbiAgfVxuICBjb21taXQobXlfdmVjKTtcbn1cbmBcbn1cbiIsIm1vZHVsZS5leHBvcnRzID0gYFxudm9pZCBtYWluKCkge1xuICBpbml0KCk7XG4gIGl2ZWM0IG15X3ZlYyA9IHJlYWQoKTtcbiAgaWYobXlfY29vcmQueSA9PSAwICYmIG15X2Nvb3JkLnggPT0gU1RBVEVfTEVOR1RIKSB7XG4gICAgbXlfdmVjLmcgPSBjaGVjayhteV92ZWMuYiwgbXlfdmVjLnIpO1xuICB9XG4gIGlmKG15X2Nvb3JkLnkgPT0gMCAmJiBteV9jb29yZC54IDwgSEFTSF9MRU5HVEgpIHtcbiAgICBpdmVjNCBpbmZvX3ZlYyA9IHJlYWRfYXQoaXZlYzIoU1RBVEVfTEVOR1RILCAwKSk7XG4gICAgaW50IG5vbmNlX3Byb2JlID0gaW5mb192ZWMuYTtcbiAgICBpbnQgcm93ID0gaW5mb192ZWMuYjtcbiAgICBpdmVjNCBoYXNoX3ZlYyA9IHJlYWRfYXQoaXZlYzIobXlfY29vcmQueCwgcm93KSk7XG4gICAgbXlfdmVjLmEgPSAoaGFzaF92ZWMuciAmIG5vbmNlX3Byb2JlKSA9PSAwPyAxIDogKChoYXNoX3ZlYy5nICYgbm9uY2VfcHJvYmUpID09IDA/IC0xIDogMCk7XG4gIH1cbiAgY29tbWl0KG15X3ZlYyk7XG59XG5gXG4iLCJtb2R1bGUuZXhwb3J0cyA9IFxuYCNkZWZpbmUgSEFTSF9MRU5HVEggMjQzXG4jZGVmaW5lIE5VTUJFUl9PRl9ST1VORFMgODFcbiNkZWZpbmUgSU5DUkVNRU5UX1NUQVJUIEhBU0hfTEVOR1RIIC0gNjRcbiNkZWZpbmUgU1RBVEVfTEVOR1RIIDMgKiBIQVNIX0xFTkdUSFxuI2RlZmluZSBIQUxGX0xFTkdUSCAzNjRcbiNkZWZpbmUgSElHSF9CSVRTIDB4RkZGRkZGRkZcbiNkZWZpbmUgTE9XX0JJVFMgMHgwMDAwMDAwMFxuYFxuIiwibW9kdWxlLmV4cG9ydHMgPSBgXG52b2lkIG1haW4oKSB7XG4gIGluaXQoKTtcbiAgaXZlYzQgbXlfdmVjID0gcmVhZCgpO1xuICBpZihteV9jb29yZC54ID49IElOQ1JFTUVOVF9TVEFSVCAmJiBteV9jb29yZC54IDwgSEFTSF9MRU5HVEggKSB7XG4gICAgbXlfdmVjLnJnID0gZ2V0X3N1bV90b19pbmRleChJTkNSRU1FTlRfU1RBUlQsIEhBU0hfTEVOR1RILCAxLCBteV9jb29yZC55KTtcbiAgfVxuICBpZihteV9jb29yZC54ID09IFNUQVRFX0xFTkdUSCApIHtcbiAgICBteV92ZWMucmcgPSBpdmVjMigwKTtcbiAgfVxuICBteV92ZWMuYmEgPSBteV92ZWMucmc7XG4gIGNvbW1pdChteV92ZWMpO1xufVxuYFxuIiwiY29uc3QgaGVhZGVycyAgICA9IHJlcXVpcmUoICcuL2hlYWRlcnMnKTtcbmNvbnN0IGZpbmFsaXplICAgPSByZXF1aXJlKCAnLi9maW5hbGl6ZScpO1xuY29uc3QgYmFycmllciAgICA9IHJlcXVpcmUoICcuL2JhcnJpZXInKTtcbmNvbnN0IHR3aXN0ICAgICAgPSByZXF1aXJlKCAnLi90cmFuc2Zvcm0nKTtcbmNvbnN0IGNoZWNrICAgICAgPSByZXF1aXJlKCAnLi9jaGVjaycpO1xuY29uc3QgYWRkICAgICAgICA9IHJlcXVpcmUoICcuL2FkZCcpO1xuY29uc3QgaW5pdCAgICAgICA9IHJlcXVpcmUoICcuL2luaXQnKTtcbmNvbnN0IGluY3JlbWVudCAgPSByZXF1aXJlKCAnLi9pbmNyZW1lbnQnKTtcblxubW9kdWxlLmV4cG9ydHMgPSB7XG4gIGluaXQgICAgICA6IGhlYWRlcnMgKyBhZGQgKyBpbml0LFxuICBpbmNyZW1lbnQgOiBoZWFkZXJzICsgYWRkICsgaW5jcmVtZW50LFxuICB0cmFuc2Zvcm0gOiBoZWFkZXJzICsgdHdpc3QsXG4gIGNvbF9jaGVjayA6IGhlYWRlcnMgKyBjaGVjay5jb2wsXG4gIGNoZWNrICAgICA6IGhlYWRlcnMgKyBjaGVjay5kb19jaGVjayArIGNoZWNrLmtfY2hlY2ssXG4gIGZpbmFsaXplICA6IGhlYWRlcnMgKyBjaGVjay5kb19jaGVjayArIGZpbmFsaXplLFxufVxuIiwibGV0IGtfaW5pdCA9IGBcbnZvaWQgbWFpbigpIHtcbiAgaW5pdCgpO1xuICBjb21taXQob2Zmc2V0KCkpO1xufVxuYFxubGV0IG9mZnNldCA9IGBcbnVuaWZvcm0gaW50IGdyX29mZnNldDtcbml2ZWM0IG9mZnNldCgpIHtcbiAgaWYobXlfY29vcmQueCA+PSBIQVNIX0xFTkdUSCAvIDMgJiYgbXlfY29vcmQueCA8IEhBU0hfTEVOR1RIIC8gMyAqIDIgKSB7XG4gICAgaXZlYzQgbXlfdmVjO1xuICAgIG15X3ZlYy5yZyA9IGdldF9zdW1fdG9faW5kZXgoSEFTSF9MRU5HVEggLyAzLCBIQVNIX0xFTkdUSCAvIDMgKiAyLCBteV9jb29yZC55ICsgZ3Jfb2Zmc2V0LCAwKTtcbiAgICByZXR1cm4gbXlfdmVjO1xuICB9IGVsc2Uge1xuICAgIHJldHVybiByZWFkX2F0KGl2ZWMyKG15X2Nvb3JkLngsMCkpO1xuICB9XG59XG5gXG5tb2R1bGUuZXhwb3J0cyA9IG9mZnNldCArIGtfaW5pdFxuIiwibGV0IHR3aXN0ID0gYFxuaXZlYzIgdHdpc3QoKSB7XG4gIGludCBhbHBoYSwgYmV0YSwgZ2FtbWEsIGRlbHRhO1xuICBpdmVjNCB2MSwgdjI7XG4gIGludCBqID0gbXlfY29vcmQueDtcblxuICB2MSA9IHJlYWRfYXQoaXZlYzIoaiA9PSAwPyAwOigoKGogLSAxKSUyKSsxKSpIQUxGX0xFTkdUSCAtICgoai0xKT4+MSksIG15X2Nvb3JkLnkpKTtcbiAgdjIgPSByZWFkX2F0KGl2ZWMyKCgoaiUyKSsxKSpIQUxGX0xFTkdUSCAtICgoaik+PjEpLCBteV9jb29yZC55KSk7XG4gIGFscGhhID0gdjEuYjtcbiAgYmV0YSA9IHYxLmE7XG4gIGdhbW1hID0gdjIuYTtcbiAgZGVsdGEgPSAoYWxwaGEgfCAofmdhbW1hKSkgJiAodjIuYiBeIGJldGEpOy8vdjIuYiA9PT0gc3RhdGVfbG93W3QyXVxuXG4gIHJldHVybiBpdmVjMih+ZGVsdGEsIChhbHBoYSBeIGdhbW1hKSB8IGRlbHRhKTtcbn1cbmBcbmxldCAgdHdpc3RNYWluID0gYFxudm9pZCBtYWluKCkge1xuICBpbml0KCk7XG4gIGl2ZWM0IG15X3ZlYyA9IHJlYWQoKTtcbiAgaWYobXlfY29vcmQueCA8IFNUQVRFX0xFTkdUSClcbiAgICBteV92ZWMuYmEgPSB0d2lzdCgpO1xuICBjb21taXQobXlfdmVjKTtcbn1cbmBcblxubGV0IGtfdHJhbnNmb3JtID0gYFxudm9pZCB0cmFuc2Zvcm0oKSB7XG4gIGl2ZWMyIHNjcmF0Y2hwYWQ7XG4gIGl2ZWM0IHN0YXRlID0gcmVhZCgpO1xuICBpbnQgcm91bmQ7XG4gIGZvcihyb3VuZCA9IDA7IHJvdW5kIDwgTlVNQkVSX09GX1JPVU5EUzsgcm91bmQrKykge1xuICAgIHNjcmF0Y2hwYWQgPSB0d2lzdCgpO1xuICAgIC8vYmFycmllcihpdmVjMihTVEFURV9MRU5HVEgsbXlfY29vcmQueSksIDApO1xuICAgIHN0YXRlLmIgPSBzY3JhdGNocGFkLnM7Ly9zcF9sb3dbaV07XG4gICAgc3RhdGUuYSA9IHNjcmF0Y2hwYWQudDsvL3NwX2hpZ2hbaV07XG4gICAgY29tbWl0KHN0YXRlKTtcbiAgICAvL2JhcnJpZXIoaXZlYzIoU1RBVEVfTEVOR1RILG15X2Nvb3JkLnkpLCAwKTtcbiAgfVxufVxuYFxuXG5tb2R1bGUuZXhwb3J0cyA9IHR3aXN0ICsgdHdpc3RNYWluXG4iXSwic291cmNlUm9vdCI6IiJ9