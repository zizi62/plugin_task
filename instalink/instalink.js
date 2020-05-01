/* 
	InstaLink
	Version: 2.1.4
	Release date: Fri Oct 12 2018
	
	elfsight.com
	
	Copyright (c) 2018 Elfsight, LLC. ALL RIGHTS RESERVED
 */


(function(window, undefined) {
    var dependencies = [
        {
            src: 'https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js',
            test: function () {
                return !!window.jQuery && compareVersions(window.jQuery.fn.jquery, '1.7.0') === 1;
            }
        }
    ];

    function compareVersions(a, b) {
        if (a === b) {
            return 0;
        }

        var aParts = a.split(".");
        var bParts = b.split(".");

        var len = Math.min(aParts.length, bParts.length);

        for (var i = 0; i < len; i++) {
            if (parseInt(aParts[i]) > parseInt(bParts[i])) {
                return 1;
            }

            if (parseInt(aParts[i]) < parseInt(bParts[i])) {
                return -1;
            }
        }

        if (aParts.length > bParts.length) {
            return 1;
        }

        if (aParts.length < bParts.length) {
            return -1;
        }

        return 0;
    }

    function loadDependencies(callback) {
        var count = 0;
        var loaded = 0;

        for (var i = 0; i < dependencies.length; ++i) (function(i, dep) {
            if (dep.test.call()) {
                return;
            }

            ++count;

            var script = document.createElement('script');

            script.src = dep.src;
            script.onload = function() {
                if (++loaded === count) {
                    callback();
                }

            };

            document.head.appendChild(script);

        }).call(dependencies[i], i, dependencies[i]);

        if (!count) {
            callback();
        }
    }

    var
        /**
         * Contains count of widgets on the page
         * @member {number}
         */
        widgetsCount = 0;

    /**
    * @license Gibberish-AES 
    * A lightweight Javascript Libray for OpenSSL compatible AES CBC encryption.
    *
    * Author: Mark Percival
    * Email: mark@mpercival.com
    * Copyright: Mark Percival - http://mpercival.com 2008
    *
    * With thanks to:
    * Josh Davis - http://www.josh-davis.org/ecmaScrypt
    * Chris Veness - http://www.movable-type.co.uk/scripts/aes.html
    * Michel I. Gallant - http://www.jensign.com/
    * Jean-Luc Cooke <jlcooke@certainkey.com> 2012-07-12: added strhex + invertArr to compress G2X/G3X/G9X/GBX/GEX/SBox/SBoxInv/Rcon saving over 7KB, and added encString, decString, also made the MD5 routine more easlier compressible using yuicompressor.
    *
    * License: MIT
    *
    * Usage: GibberishAES.enc("secret", "password")
    * Outputs: AES Encrypted text encoded in Base64
    */
    
    
    (function (root, factory) {
        if (typeof exports === 'object') {
            // Node. 
            module.exports = factory();
        } else if (typeof define === 'function' && define.amd) {
            // AMD. Register as an anonymous module.
            define(factory);
        } else {
            // Browser globals (root is window)
            root.GibberishAES = factory();
        }
    }(this, function () {
        'use strict';
    
        var Nr = 14,
        /* Default to 256 Bit Encryption */
        Nk = 8,
        Decrypt = false,
    
        enc_utf8 = function(s)
        {
            try {
                return unescape(encodeURIComponent(s));
            }
            catch(e) {
                throw 'Error on UTF-8 encode';
            }
        },
    
        dec_utf8 = function(s)
        {
            try {
                return decodeURIComponent(escape(s));
            }
            catch(e) {
                throw ('Bad Key');
            }
        },
    
        padBlock = function(byteArr)
        {
            var array = [], cpad, i;
            if (byteArr.length < 16) {
                cpad = 16 - byteArr.length;
                array = [cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad, cpad];
            }
            for (i = 0; i < byteArr.length; i++)
            {
                array[i] = byteArr[i];
            }
            return array;
        },
    
        block2s = function(block, lastBlock)
        {
            var string = '', padding, i;
            if (lastBlock) {
                padding = block[15];
                if (padding > 16) {
                    throw ('Decryption error: Maybe bad key');
                }
                if (padding === 16) {
                    return '';
                }
                for (i = 0; i < 16 - padding; i++) {
                    string += String.fromCharCode(block[i]);
                }
            } else {
                for (i = 0; i < 16; i++) {
                    string += String.fromCharCode(block[i]);
                }
            }
            return string;
        },
    
        a2h = function(numArr)
        {
            var string = '', i;
            for (i = 0; i < numArr.length; i++) {
                string += (numArr[i] < 16 ? '0': '') + numArr[i].toString(16);
            }
            return string;
        },
    
        h2a = function(s)
        {
            var ret = [];
            s.replace(/(..)/g,
            function(s) {
                ret.push(parseInt(s, 16));
            });
            return ret;
        },
    
        s2a = function(string, binary) {
            var array = [], i;
    
            if (! binary) {
                string = enc_utf8(string);
            }
    
            for (i = 0; i < string.length; i++)
            {
                array[i] = string.charCodeAt(i);
            }
    
            return array;
        },
    
        size = function(newsize)
        {
            switch (newsize)
            {
            case 128:
                Nr = 10;
                Nk = 4;
                break;
            case 192:
                Nr = 12;
                Nk = 6;
                break;
            case 256:
                Nr = 14;
                Nk = 8;
                break;
            default:
                throw ('Invalid Key Size Specified:' + newsize);
            }
        },
    
        randArr = function(num) {
            var result = [], i;
            for (i = 0; i < num; i++) {
                result = result.concat(Math.floor(Math.random() * 256));
            }
            return result;
        },
    
        openSSLKey = function(passwordArr, saltArr) {
            // Number of rounds depends on the size of the AES in use
            // 3 rounds for 256
            //        2 rounds for the key, 1 for the IV
            // 2 rounds for 128
            //        1 round for the key, 1 round for the IV
            // 3 rounds for 192 since it's not evenly divided by 128 bits
            var rounds = Nr >= 12 ? 3: 2,
            key = [],
            iv = [],
            md5_hash = [],
            result = [],
            data00 = passwordArr.concat(saltArr),
            i;
            md5_hash[0] = MD5(data00);
            result = md5_hash[0];
            for (i = 1; i < rounds; i++) {
                md5_hash[i] = MD5(md5_hash[i - 1].concat(data00));
                result = result.concat(md5_hash[i]);
            }
            key = result.slice(0, 4 * Nk);
            iv = result.slice(4 * Nk, 4 * Nk + 16);
            return {
                key: key,
                iv: iv
            };
        },
    
        rawEncrypt = function(plaintext, key, iv) {
            // plaintext, key and iv as byte arrays
            key = expandKey(key);
            var numBlocks = Math.ceil(plaintext.length / 16),
            blocks = [],
            i,
            cipherBlocks = [];
            for (i = 0; i < numBlocks; i++) {
                blocks[i] = padBlock(plaintext.slice(i * 16, i * 16 + 16));
            }
            if (plaintext.length % 16 === 0) {
                blocks.push([16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]);
                // CBC OpenSSL padding scheme
                numBlocks++;
            }
            for (i = 0; i < blocks.length; i++) {
                blocks[i] = (i === 0) ? xorBlocks(blocks[i], iv) : xorBlocks(blocks[i], cipherBlocks[i - 1]);
                cipherBlocks[i] = encryptBlock(blocks[i], key);
            }
            return cipherBlocks;
        },
    
        rawDecrypt = function(cryptArr, key, iv, binary) {
            //  cryptArr, key and iv as byte arrays
            key = expandKey(key);
            var numBlocks = cryptArr.length / 16,
            cipherBlocks = [],
            i,
            plainBlocks = [],
            string = '';
            for (i = 0; i < numBlocks; i++) {
                cipherBlocks.push(cryptArr.slice(i * 16, (i + 1) * 16));
            }
            for (i = cipherBlocks.length - 1; i >= 0; i--) {
                plainBlocks[i] = decryptBlock(cipherBlocks[i], key);
                plainBlocks[i] = (i === 0) ? xorBlocks(plainBlocks[i], iv) : xorBlocks(plainBlocks[i], cipherBlocks[i - 1]);
            }
            for (i = 0; i < numBlocks - 1; i++) {
                string += block2s(plainBlocks[i]);
            }
            string += block2s(plainBlocks[i], true);
            return binary ? string : dec_utf8(string); 
        },
    
        encryptBlock = function(block, words) {
            Decrypt = false;
            var state = addRoundKey(block, words, 0),
            round;
            for (round = 1; round < (Nr + 1); round++) {
                state = subBytes(state);
                state = shiftRows(state);
                if (round < Nr) {
                    state = mixColumns(state);
                }
                //last round? don't mixColumns
                state = addRoundKey(state, words, round);
            }
    
            return state;
        },
    
        decryptBlock = function(block, words) {
            Decrypt = true;
            var state = addRoundKey(block, words, Nr),
            round;
            for (round = Nr - 1; round > -1; round--) {
                state = shiftRows(state);
                state = subBytes(state);
                state = addRoundKey(state, words, round);
                if (round > 0) {
                    state = mixColumns(state);
                }
                //last round? don't mixColumns
            }
    
            return state;
        },
    
        subBytes = function(state) {
            var S = Decrypt ? SBoxInv: SBox,
            temp = [],
            i;
            for (i = 0; i < 16; i++) {
                temp[i] = S[state[i]];
            }
            return temp;
        },
    
        shiftRows = function(state) {
            var temp = [],
            shiftBy = Decrypt ? [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3] : [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11],
            i;
            for (i = 0; i < 16; i++) {
                temp[i] = state[shiftBy[i]];
            }
            return temp;
        },
    
        mixColumns = function(state) {
            var t = [],
            c;
            if (!Decrypt) {
                for (c = 0; c < 4; c++) {
                    t[c * 4] = G2X[state[c * 4]] ^ G3X[state[1 + c * 4]] ^ state[2 + c * 4] ^ state[3 + c * 4];
                    t[1 + c * 4] = state[c * 4] ^ G2X[state[1 + c * 4]] ^ G3X[state[2 + c * 4]] ^ state[3 + c * 4];
                    t[2 + c * 4] = state[c * 4] ^ state[1 + c * 4] ^ G2X[state[2 + c * 4]] ^ G3X[state[3 + c * 4]];
                    t[3 + c * 4] = G3X[state[c * 4]] ^ state[1 + c * 4] ^ state[2 + c * 4] ^ G2X[state[3 + c * 4]];
                }
            }else {
                for (c = 0; c < 4; c++) {
                    t[c*4] = GEX[state[c*4]] ^ GBX[state[1+c*4]] ^ GDX[state[2+c*4]] ^ G9X[state[3+c*4]];
                    t[1+c*4] = G9X[state[c*4]] ^ GEX[state[1+c*4]] ^ GBX[state[2+c*4]] ^ GDX[state[3+c*4]];
                    t[2+c*4] = GDX[state[c*4]] ^ G9X[state[1+c*4]] ^ GEX[state[2+c*4]] ^ GBX[state[3+c*4]];
                    t[3+c*4] = GBX[state[c*4]] ^ GDX[state[1+c*4]] ^ G9X[state[2+c*4]] ^ GEX[state[3+c*4]];
                }
            }
            
            return t;
        },
    
        addRoundKey = function(state, words, round) {
            var temp = [],
            i;
            for (i = 0; i < 16; i++) {
                temp[i] = state[i] ^ words[round][i];
            }
            return temp;
        },
    
        xorBlocks = function(block1, block2) {
            var temp = [],
            i;
            for (i = 0; i < 16; i++) {
                temp[i] = block1[i] ^ block2[i];
            }
            return temp;
        },
    
        expandKey = function(key) {
            // Expects a 1d number array
            var w = [],
            temp = [],
            i,
            r,
            t,
            flat = [],
            j;
    
            for (i = 0; i < Nk; i++) {
                r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
                w[i] = r;
            }
    
            for (i = Nk; i < (4 * (Nr + 1)); i++) {
                w[i] = [];
                for (t = 0; t < 4; t++) {
                    temp[t] = w[i - 1][t];
                }
                if (i % Nk === 0) {
                    temp = subWord(rotWord(temp));
                    temp[0] ^= Rcon[i / Nk - 1];
                } else if (Nk > 6 && i % Nk === 4) {
                    temp = subWord(temp);
                }
                for (t = 0; t < 4; t++) {
                    w[i][t] = w[i - Nk][t] ^ temp[t];
                }
            }
            for (i = 0; i < (Nr + 1); i++) {
                flat[i] = [];
                for (j = 0; j < 4; j++) {
                    flat[i].push(w[i * 4 + j][0], w[i * 4 + j][1], w[i * 4 + j][2], w[i * 4 + j][3]);
                }
            }
            return flat;
        },
    
        subWord = function(w) {
            // apply SBox to 4-byte word w
            for (var i = 0; i < 4; i++) {
                w[i] = SBox[w[i]];
            }
            return w;
        },
    
        rotWord = function(w) {
            // rotate 4-byte word w left by one byte
            var tmp = w[0],
            i;
            for (i = 0; i < 4; i++) {
                w[i] = w[i + 1];
            }
            w[3] = tmp;
            return w;
        },
    
    // jlcooke: 2012-07-12: added strhex + invertArr to compress G2X/G3X/G9X/GBX/GEX/SBox/SBoxInv/Rcon saving over 7KB, and added encString, decString
        strhex = function(str,size) {
            var i, ret = [];
            for (i=0; i<str.length; i+=size){
                ret[i/size] = parseInt(str.substr(i,size), 16);
            }
            return ret;
        },
        invertArr = function(arr) {
            var i, ret = [];
            for (i=0; i<arr.length; i++){
                ret[arr[i]] = i;
            }
            return ret;
        },
        Gxx = function(a, b) {
            var i, ret;
    
            ret = 0;
            for (i=0; i<8; i++) {
                ret = ((b&1)===1) ? ret^a : ret;
                /* xmult */
                a = (a>0x7f) ? 0x11b^(a<<1) : (a<<1);
                b >>>= 1;
            }
    
            return ret;
        },
        Gx = function(x) {
            var i, r = [];
            for (i=0; i<256; i++){
                r[i] = Gxx(x, i);
            }
            return r;
        },
    
        // S-box
    /*
        SBox = [
        99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171,
        118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164,
        114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113,
        216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226,
        235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214,
        179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203,
        190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69,
        249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245,
        188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68,
        23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42,
        144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73,
        6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109,
        141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37,
        46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62,
        181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225,
        248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
        140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187,
        22], //*/ SBox = strhex('637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16',2),
    
        // Precomputed lookup table for the inverse SBox
    /*    SBoxInv = [
        82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215,
        251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222,
        233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66,
        250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73,
        109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92,
        204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21,
        70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247,
        228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2,
        193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220,
        234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173,
        53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29,
        41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75,
        198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168,
        51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81,
        127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160,
        224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
        23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12,
        125], //*/ SBoxInv = invertArr(SBox),
    
        // Rijndael Rcon
    /*
        Rcon = [1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94,
        188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145],
    //*/ Rcon = strhex('01020408102040801b366cd8ab4d9a2f5ebc63c697356ad4b37dfaefc591',2),
    
    /*
        G2X = [
        0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12, 0x14, 0x16,
        0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
        0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46,
        0x48, 0x4a, 0x4c, 0x4e, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e,
        0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76,
        0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
        0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e, 0xa0, 0xa2, 0xa4, 0xa6,
        0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe,
        0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6,
        0xd8, 0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
        0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 0x1b, 0x19, 0x1f, 0x1d,
        0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07, 0x05,
        0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d,
        0x23, 0x21, 0x27, 0x25, 0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
        0x4b, 0x49, 0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45, 0x7b, 0x79, 0x7f, 0x7d,
        0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67, 0x65,
        0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95, 0x8b, 0x89, 0x8f, 0x8d,
        0x83, 0x81, 0x87, 0x85, 0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
        0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7, 0xa5, 0xdb, 0xd9, 0xdf, 0xdd,
        0xd3, 0xd1, 0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
        0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9, 0xef, 0xed,
        0xe3, 0xe1, 0xe7, 0xe5
        ], //*/ G2X = Gx(2),
    
    /*    G3X = [
        0x00, 0x03, 0x06, 0x05, 0x0c, 0x0f, 0x0a, 0x09, 0x18, 0x1b, 0x1e, 0x1d,
        0x14, 0x17, 0x12, 0x11, 0x30, 0x33, 0x36, 0x35, 0x3c, 0x3f, 0x3a, 0x39,
        0x28, 0x2b, 0x2e, 0x2d, 0x24, 0x27, 0x22, 0x21, 0x60, 0x63, 0x66, 0x65,
        0x6c, 0x6f, 0x6a, 0x69, 0x78, 0x7b, 0x7e, 0x7d, 0x74, 0x77, 0x72, 0x71,
        0x50, 0x53, 0x56, 0x55, 0x5c, 0x5f, 0x5a, 0x59, 0x48, 0x4b, 0x4e, 0x4d,
        0x44, 0x47, 0x42, 0x41, 0xc0, 0xc3, 0xc6, 0xc5, 0xcc, 0xcf, 0xca, 0xc9,
        0xd8, 0xdb, 0xde, 0xdd, 0xd4, 0xd7, 0xd2, 0xd1, 0xf0, 0xf3, 0xf6, 0xf5,
        0xfc, 0xff, 0xfa, 0xf9, 0xe8, 0xeb, 0xee, 0xed, 0xe4, 0xe7, 0xe2, 0xe1,
        0xa0, 0xa3, 0xa6, 0xa5, 0xac, 0xaf, 0xaa, 0xa9, 0xb8, 0xbb, 0xbe, 0xbd,
        0xb4, 0xb7, 0xb2, 0xb1, 0x90, 0x93, 0x96, 0x95, 0x9c, 0x9f, 0x9a, 0x99,
        0x88, 0x8b, 0x8e, 0x8d, 0x84, 0x87, 0x82, 0x81, 0x9b, 0x98, 0x9d, 0x9e,
        0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8f, 0x8c, 0x89, 0x8a,
        0xab, 0xa8, 0xad, 0xae, 0xa7, 0xa4, 0xa1, 0xa2, 0xb3, 0xb0, 0xb5, 0xb6,
        0xbf, 0xbc, 0xb9, 0xba, 0xfb, 0xf8, 0xfd, 0xfe, 0xf7, 0xf4, 0xf1, 0xf2,
        0xe3, 0xe0, 0xe5, 0xe6, 0xef, 0xec, 0xe9, 0xea, 0xcb, 0xc8, 0xcd, 0xce,
        0xc7, 0xc4, 0xc1, 0xc2, 0xd3, 0xd0, 0xd5, 0xd6, 0xdf, 0xdc, 0xd9, 0xda,
        0x5b, 0x58, 0x5d, 0x5e, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46,
        0x4f, 0x4c, 0x49, 0x4a, 0x6b, 0x68, 0x6d, 0x6e, 0x67, 0x64, 0x61, 0x62,
        0x73, 0x70, 0x75, 0x76, 0x7f, 0x7c, 0x79, 0x7a, 0x3b, 0x38, 0x3d, 0x3e,
        0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2f, 0x2c, 0x29, 0x2a,
        0x0b, 0x08, 0x0d, 0x0e, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16,
        0x1f, 0x1c, 0x19, 0x1a
        ], //*/ G3X = Gx(3),
    
    /*
        G9X = [
        0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53,
        0x6c, 0x65, 0x7e, 0x77, 0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf,
        0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7, 0x3b, 0x32, 0x29, 0x20,
        0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
        0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8,
        0xc7, 0xce, 0xd5, 0xdc, 0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49,
        0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01, 0xe6, 0xef, 0xf4, 0xfd,
        0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
        0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e,
        0x21, 0x28, 0x33, 0x3a, 0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2,
        0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa, 0xec, 0xe5, 0xfe, 0xf7,
        0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
        0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f,
        0x10, 0x19, 0x02, 0x0b, 0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8,
        0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0, 0x47, 0x4e, 0x55, 0x5c,
        0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
        0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9,
        0xf6, 0xff, 0xe4, 0xed, 0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35,
        0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d, 0xa1, 0xa8, 0xb3, 0xba,
        0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
        0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62,
        0x5d, 0x54, 0x4f, 0x46
        ], //*/ G9X = Gx(9),
    
    /*    GBX = [
        0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45,
        0x74, 0x7f, 0x62, 0x69, 0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81,
        0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9, 0x7b, 0x70, 0x6d, 0x66,
        0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
        0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e,
        0xbf, 0xb4, 0xa9, 0xa2, 0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7,
        0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f, 0x46, 0x4d, 0x50, 0x5b,
        0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
        0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8,
        0xf9, 0xf2, 0xef, 0xe4, 0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c,
        0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54, 0xf7, 0xfc, 0xe1, 0xea,
        0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
        0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02,
        0x33, 0x38, 0x25, 0x2e, 0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd,
        0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5, 0x3c, 0x37, 0x2a, 0x21,
        0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
        0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44,
        0x75, 0x7e, 0x63, 0x68, 0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80,
        0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8, 0x7a, 0x71, 0x6c, 0x67,
        0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
        0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f,
        0xbe, 0xb5, 0xa8, 0xa3
        ], //*/ GBX = Gx(0xb),
    
    /*
        GDX = [
        0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f,
        0x5c, 0x51, 0x46, 0x4b, 0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3,
        0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b, 0xbb, 0xb6, 0xa1, 0xac,
        0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
        0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14,
        0x37, 0x3a, 0x2d, 0x20, 0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e,
        0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26, 0xbd, 0xb0, 0xa7, 0xaa,
        0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
        0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9,
        0x8a, 0x87, 0x90, 0x9d, 0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25,
        0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d, 0xda, 0xd7, 0xc0, 0xcd,
        0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
        0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75,
        0x56, 0x5b, 0x4c, 0x41, 0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42,
        0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a, 0xb1, 0xbc, 0xab, 0xa6,
        0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
        0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8,
        0xeb, 0xe6, 0xf1, 0xfc, 0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44,
        0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c, 0x0c, 0x01, 0x16, 0x1b,
        0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
        0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3,
        0x80, 0x8d, 0x9a, 0x97
        ], //*/ GDX = Gx(0xd),
    
    /*
        GEX = [
        0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62,
        0x48, 0x46, 0x54, 0x5a, 0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca,
        0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba, 0xdb, 0xd5, 0xc7, 0xc9,
        0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
        0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59,
        0x73, 0x7d, 0x6f, 0x61, 0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87,
        0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7, 0x4d, 0x43, 0x51, 0x5f,
        0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
        0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14,
        0x3e, 0x30, 0x22, 0x2c, 0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc,
        0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc, 0x41, 0x4f, 0x5d, 0x53,
        0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
        0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3,
        0xe9, 0xe7, 0xf5, 0xfb, 0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0,
        0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0, 0x7a, 0x74, 0x66, 0x68,
        0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
        0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e,
        0xa4, 0xaa, 0xb8, 0xb6, 0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26,
        0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56, 0x37, 0x39, 0x2b, 0x25,
        0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
        0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5,
        0x9f, 0x91, 0x83, 0x8d
        ], //*/ GEX = Gx(0xe),
    
        enc = function(string, pass, binary) {
            // string, password in plaintext
            var salt = randArr(8),
            pbe = openSSLKey(s2a(pass, binary), salt),
            key = pbe.key,
            iv = pbe.iv,
            cipherBlocks,
            saltBlock = [[83, 97, 108, 116, 101, 100, 95, 95].concat(salt)];
            string = s2a(string, binary);
            cipherBlocks = rawEncrypt(string, key, iv);
            // Spells out 'Salted__'
            cipherBlocks = saltBlock.concat(cipherBlocks);
            return Base64.encode(cipherBlocks);
        },
    
        dec = function(string, pass, binary) {
            // string, password in plaintext
            var cryptArr = Base64.decode(string),
            salt = cryptArr.slice(8, 16),
            pbe = openSSLKey(s2a(pass, binary), salt),
            key = pbe.key,
            iv = pbe.iv;
            cryptArr = cryptArr.slice(16, cryptArr.length);
            // Take off the Salted__ffeeddcc
            string = rawDecrypt(cryptArr, key, iv, binary);
            return string;
        },
        
        MD5 = function(numArr) {
    
            function rotateLeft(lValue, iShiftBits) {
                return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
            }
    
            function addUnsigned(lX, lY) {
                var lX4,
                lY4,
                lX8,
                lY8,
                lResult;
                lX8 = (lX & 0x80000000);
                lY8 = (lY & 0x80000000);
                lX4 = (lX & 0x40000000);
                lY4 = (lY & 0x40000000);
                lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
                if (lX4 & lY4) {
                    return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
                }
                if (lX4 | lY4) {
                    if (lResult & 0x40000000) {
                        return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
                    } else {
                        return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
                    }
                } else {
                    return (lResult ^ lX8 ^ lY8);
                }
            }
    
            function f(x, y, z) {
                return (x & y) | ((~x) & z);
            }
            function g(x, y, z) {
                return (x & z) | (y & (~z));
            }
            function h(x, y, z) {
                return (x ^ y ^ z);
            }
            function funcI(x, y, z) {
                return (y ^ (x | (~z)));
            }
    
            function ff(a, b, c, d, x, s, ac) {
                a = addUnsigned(a, addUnsigned(addUnsigned(f(b, c, d), x), ac));
                return addUnsigned(rotateLeft(a, s), b);
            }
    
            function gg(a, b, c, d, x, s, ac) {
                a = addUnsigned(a, addUnsigned(addUnsigned(g(b, c, d), x), ac));
                return addUnsigned(rotateLeft(a, s), b);
            }
    
            function hh(a, b, c, d, x, s, ac) {
                a = addUnsigned(a, addUnsigned(addUnsigned(h(b, c, d), x), ac));
                return addUnsigned(rotateLeft(a, s), b);
            }
    
            function ii(a, b, c, d, x, s, ac) {
                a = addUnsigned(a, addUnsigned(addUnsigned(funcI(b, c, d), x), ac));
                return addUnsigned(rotateLeft(a, s), b);
            }
    
            function convertToWordArray(numArr) {
                var lWordCount,
                lMessageLength = numArr.length,
                lNumberOfWords_temp1 = lMessageLength + 8,
                lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64,
                lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16,
                lWordArray = [],
                lBytePosition = 0,
                lByteCount = 0;
                while (lByteCount < lMessageLength) {
                    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
                    lBytePosition = (lByteCount % 4) * 8;
                    lWordArray[lWordCount] = (lWordArray[lWordCount] | (numArr[lByteCount] << lBytePosition));
                    lByteCount++;
                }
                lWordCount = (lByteCount - (lByteCount % 4)) / 4;
                lBytePosition = (lByteCount % 4) * 8;
                lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
                lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
                lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
                return lWordArray;
            }
    
            function wordToHex(lValue) {
                var lByte,
                lCount,
                wordToHexArr = [];
                for (lCount = 0; lCount <= 3; lCount++) {
                    lByte = (lValue >>> (lCount * 8)) & 255;
                    wordToHexArr = wordToHexArr.concat(lByte);
                 }
                return wordToHexArr;
            }
    
            /*function utf8Encode(string) {
                string = string.replace(/\r\n/g, "\n");
                var utftext = "",
                n,
                c;
    
                for (n = 0; n < string.length; n++) {
    
                    c = string.charCodeAt(n);
    
                    if (c < 128) {
                        utftext += String.fromCharCode(c);
                    }
                    else if ((c > 127) && (c < 2048)) {
                        utftext += String.fromCharCode((c >> 6) | 192);
                        utftext += String.fromCharCode((c & 63) | 128);
                    }
                    else {
                        utftext += String.fromCharCode((c >> 12) | 224);
                        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                        utftext += String.fromCharCode((c & 63) | 128);
                    }
    
                }
    
                return utftext;
            }*/
    
            var x = [],
            k,
            AA,
            BB,
            CC,
            DD,
            a,
            b,
            c,
            d,
            rnd = strhex('67452301efcdab8998badcfe10325476d76aa478e8c7b756242070dbc1bdceeef57c0faf4787c62aa8304613fd469501698098d88b44f7afffff5bb1895cd7be6b901122fd987193a679438e49b40821f61e2562c040b340265e5a51e9b6c7aad62f105d02441453d8a1e681e7d3fbc821e1cde6c33707d6f4d50d87455a14eda9e3e905fcefa3f8676f02d98d2a4c8afffa39428771f6816d9d6122fde5380ca4beea444bdecfa9f6bb4b60bebfbc70289b7ec6eaa127fad4ef308504881d05d9d4d039e6db99e51fa27cf8c4ac5665f4292244432aff97ab9423a7fc93a039655b59c38f0ccc92ffeff47d85845dd16fa87e4ffe2ce6e0a30143144e0811a1f7537e82bd3af2352ad7d2bbeb86d391',8);
    
            x = convertToWordArray(numArr);
    
            a = rnd[0];
            b = rnd[1];
            c = rnd[2];
            d = rnd[3];
    
            for (k = 0; k < x.length; k += 16) {
                AA = a;
                BB = b;
                CC = c;
                DD = d;
                a = ff(a, b, c, d, x[k + 0], 7, rnd[4]);
                d = ff(d, a, b, c, x[k + 1], 12, rnd[5]);
                c = ff(c, d, a, b, x[k + 2], 17, rnd[6]);
                b = ff(b, c, d, a, x[k + 3], 22, rnd[7]);
                a = ff(a, b, c, d, x[k + 4], 7, rnd[8]);
                d = ff(d, a, b, c, x[k + 5], 12, rnd[9]);
                c = ff(c, d, a, b, x[k + 6], 17, rnd[10]);
                b = ff(b, c, d, a, x[k + 7], 22, rnd[11]);
                a = ff(a, b, c, d, x[k + 8], 7, rnd[12]);
                d = ff(d, a, b, c, x[k + 9], 12, rnd[13]);
                c = ff(c, d, a, b, x[k + 10], 17, rnd[14]);
                b = ff(b, c, d, a, x[k + 11], 22, rnd[15]);
                a = ff(a, b, c, d, x[k + 12], 7, rnd[16]);
                d = ff(d, a, b, c, x[k + 13], 12, rnd[17]);
                c = ff(c, d, a, b, x[k + 14], 17, rnd[18]);
                b = ff(b, c, d, a, x[k + 15], 22, rnd[19]);
                a = gg(a, b, c, d, x[k + 1], 5, rnd[20]);
                d = gg(d, a, b, c, x[k + 6], 9, rnd[21]);
                c = gg(c, d, a, b, x[k + 11], 14, rnd[22]);
                b = gg(b, c, d, a, x[k + 0], 20, rnd[23]);
                a = gg(a, b, c, d, x[k + 5], 5, rnd[24]);
                d = gg(d, a, b, c, x[k + 10], 9, rnd[25]);
                c = gg(c, d, a, b, x[k + 15], 14, rnd[26]);
                b = gg(b, c, d, a, x[k + 4], 20, rnd[27]);
                a = gg(a, b, c, d, x[k + 9], 5, rnd[28]);
                d = gg(d, a, b, c, x[k + 14], 9, rnd[29]);
                c = gg(c, d, a, b, x[k + 3], 14, rnd[30]);
                b = gg(b, c, d, a, x[k + 8], 20, rnd[31]);
                a = gg(a, b, c, d, x[k + 13], 5, rnd[32]);
                d = gg(d, a, b, c, x[k + 2], 9, rnd[33]);
                c = gg(c, d, a, b, x[k + 7], 14, rnd[34]);
                b = gg(b, c, d, a, x[k + 12], 20, rnd[35]);
                a = hh(a, b, c, d, x[k + 5], 4, rnd[36]);
                d = hh(d, a, b, c, x[k + 8], 11, rnd[37]);
                c = hh(c, d, a, b, x[k + 11], 16, rnd[38]);
                b = hh(b, c, d, a, x[k + 14], 23, rnd[39]);
                a = hh(a, b, c, d, x[k + 1], 4, rnd[40]);
                d = hh(d, a, b, c, x[k + 4], 11, rnd[41]);
                c = hh(c, d, a, b, x[k + 7], 16, rnd[42]);
                b = hh(b, c, d, a, x[k + 10], 23, rnd[43]);
                a = hh(a, b, c, d, x[k + 13], 4, rnd[44]);
                d = hh(d, a, b, c, x[k + 0], 11, rnd[45]);
                c = hh(c, d, a, b, x[k + 3], 16, rnd[46]);
                b = hh(b, c, d, a, x[k + 6], 23, rnd[47]);
                a = hh(a, b, c, d, x[k + 9], 4, rnd[48]);
                d = hh(d, a, b, c, x[k + 12], 11, rnd[49]);
                c = hh(c, d, a, b, x[k + 15], 16, rnd[50]);
                b = hh(b, c, d, a, x[k + 2], 23, rnd[51]);
                a = ii(a, b, c, d, x[k + 0], 6, rnd[52]);
                d = ii(d, a, b, c, x[k + 7], 10, rnd[53]);
                c = ii(c, d, a, b, x[k + 14], 15, rnd[54]);
                b = ii(b, c, d, a, x[k + 5], 21, rnd[55]);
                a = ii(a, b, c, d, x[k + 12], 6, rnd[56]);
                d = ii(d, a, b, c, x[k + 3], 10, rnd[57]);
                c = ii(c, d, a, b, x[k + 10], 15, rnd[58]);
                b = ii(b, c, d, a, x[k + 1], 21, rnd[59]);
                a = ii(a, b, c, d, x[k + 8], 6, rnd[60]);
                d = ii(d, a, b, c, x[k + 15], 10, rnd[61]);
                c = ii(c, d, a, b, x[k + 6], 15, rnd[62]);
                b = ii(b, c, d, a, x[k + 13], 21, rnd[63]);
                a = ii(a, b, c, d, x[k + 4], 6, rnd[64]);
                d = ii(d, a, b, c, x[k + 11], 10, rnd[65]);
                c = ii(c, d, a, b, x[k + 2], 15, rnd[66]);
                b = ii(b, c, d, a, x[k + 9], 21, rnd[67]);
                a = addUnsigned(a, AA);
                b = addUnsigned(b, BB);
                c = addUnsigned(c, CC);
                d = addUnsigned(d, DD);
            }
    
            return wordToHex(a).concat(wordToHex(b), wordToHex(c), wordToHex(d));
        },
    
        encString = function(plaintext, key, iv) {
            var i;
            plaintext = s2a(plaintext);
    
            key = s2a(key);
            for (i=key.length; i<32; i++){
                key[i] = 0;
            }
    
            if (iv === undefined) {
                // TODO: This is not defined anywhere... commented out...
                // iv = genIV();
            } else {
                iv = s2a(iv);
                for (i=iv.length; i<16; i++){
                    iv[i] = 0;
                }
            }
    
            var ct = rawEncrypt(plaintext, key, iv);
            var ret = [iv];
            for (i=0; i<ct.length; i++){
                ret[ret.length] = ct[i];
            }
            return Base64.encode(ret);
        },
    
        decString = function(ciphertext, key) {
            var tmp = Base64.decode(ciphertext);
            var iv = tmp.slice(0, 16);
            var ct = tmp.slice(16, tmp.length);
            var i;
    
            key = s2a(key);
            for (i=key.length; i<32; i++){
                key[i] = 0;
            }
    
            var pt = rawDecrypt(ct, key, iv, false);
            return pt;
        },
    
        Base64 = (function(){
            // Takes a Nx16x1 byte array and converts it to Base64
            var _chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
            chars = _chars.split(''),
            
            encode = function(b, withBreaks) {
                var flatArr = [],
                b64 = '',
                i,
                broken_b64,
                totalChunks = Math.floor(b.length * 16 / 3);
                for (i = 0; i < b.length * 16; i++) {
                    flatArr.push(b[Math.floor(i / 16)][i % 16]);
                }
                for (i = 0; i < flatArr.length; i = i + 3) {
                    b64 += chars[flatArr[i] >> 2];
                    b64 += chars[((flatArr[i] & 3) << 4) | (flatArr[i + 1] >> 4)];
                    if ( flatArr[i + 1] !== undefined ) {
                        b64 += chars[((flatArr[i + 1] & 15) << 2) | (flatArr[i + 2] >> 6)];
                    } else {
                        b64 += '=';
                    }
                    if ( flatArr[i + 2] !== undefined ) {
                        b64 += chars[flatArr[i + 2] & 63];
                    } else {
                        b64 += '=';
                    }
                }
                // OpenSSL is super particular about line breaks
                broken_b64 = b64.slice(0, 64) + '\n';
                for (i = 1; i < (Math.ceil(b64.length / 64)); i++) {
                    broken_b64 += b64.slice(i * 64, i * 64 + 64) + (Math.ceil(b64.length / 64) === i + 1 ? '': '\n');
                }
                return broken_b64;
            },
            
            decode = function(string) {
                string = string.replace(/\n/g, '');
                var flatArr = [],
                c = [],
                b = [],
                i;
                for (i = 0; i < string.length; i = i + 4) {
                    c[0] = _chars.indexOf(string.charAt(i));
                    c[1] = _chars.indexOf(string.charAt(i + 1));
                    c[2] = _chars.indexOf(string.charAt(i + 2));
                    c[3] = _chars.indexOf(string.charAt(i + 3));
    
                    b[0] = (c[0] << 2) | (c[1] >> 4);
                    b[1] = ((c[1] & 15) << 4) | (c[2] >> 2);
                    b[2] = ((c[2] & 3) << 6) | c[3];
                    flatArr.push(b[0], b[1], b[2]);
                }
                flatArr = flatArr.slice(0, flatArr.length - (flatArr.length % 16));
                return flatArr;
            };
            
            //internet explorer
            if(typeof Array.indexOf === "function") {
                _chars = chars;
            }
            
            /*
            //other way to solve internet explorer problem
            if(!Array.indexOf){
                Array.prototype.indexOf = function(obj){
                    for(var i=0; i<this.length; i++){
                        if(this[i]===obj){
                            return i;
                        }
                    }
                    return -1;
                }
            }
            */
            
            
            return {
                "encode": encode,
                "decode": decode
            };
        })();
    
        return {
            "size": size,
            "h2a":h2a,
            "expandKey":expandKey,
            "encryptBlock":encryptBlock,
            "decryptBlock":decryptBlock,
            "Decrypt":Decrypt,
            "s2a":s2a,
            "rawEncrypt":rawEncrypt,
            "rawDecrypt":rawDecrypt,
            "dec":dec,
            "openSSLKey":openSSLKey,
            "a2h":a2h,
            "enc":enc,
            "Hash":{"MD5":MD5},
            "Base64":Base64
        };
    
    }));

    
    // Array.prototype.filter polyfill from MDN
    if (!window.Array.prototype.filter) {
        window.Array.prototype.filter = function(fun/*, thisArg*/) {
            'use strict';
    
            if (this === undefined || this === null) {
                throw new window.TypeError();
            }
    
            var t = window.Object(this);
            var len = t.length >>> 0;
            if (typeof fun !== 'function') {
                throw new window.TypeError();
            }
    
            var res = [];
            var thisArg = arguments.length >= 2 ? arguments[1] : void 0;
            for (var i = 0; i < len; i++) {
                if (i in t) {
                    var val = t[i];
    
                    if (fun.call(thisArg, val, i, t)) {
                        res.push(val);
                    }
                }
            }
    
            return res;
        };
    }
    
    var reverseString = function(str) {
        return str.split('').reverse().join('');
    };

    /**
     * Creates  new Instagram API wrapper
     * @param clientId {string}
     * @constructor
     */
    function InstaLinkClient(clientId, accessToken, cacheMediaTime, alternativeApiUrl, isSandbox) {
        /**
         * Instagram Client ID
         * @type {string}
         * @private
         */
        this._clientId = clientId;
    
        this._accessToken = accessToken;
    
        this._lastPagination = {};
        this._initialPagination = {};
        this._loading = false;
        this._cacheMediaTime = cacheMediaTime;
        this._alternativeApiUrl = alternativeApiUrl;
        this._cachedProfile = null;
        this._isSandbox = isSandbox;
    }
    InstaLinkClient.prototype = function() {};
    
    /**
     * Instagram API URL
     * @type {string}
     * @private
     */
    
    InstaLinkClient.prototype._apiUrl = "https://api.instagram.com/v1";
    
    InstaLinkClient.prototype.getApiUrl = function() {
        if (this._alternativeApiUrl) {
            return this._alternativeApiUrl.replace(/\/*$/, '') + '/';
        }
    
        return InstaLinkClient.prototype._apiUrl;
    };
    
    InstaLinkClient.prototype.isAlternativeApi = function() {
        return this.getApiUrl() != InstaLinkClient.prototype._apiUrl;
    };
    
    InstaLinkClient.prototype.hasNextPage = function(id) {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!jQuery.isArray(id)) {
            id = [id];
        }
    
        return window.Object.keys(this._lastPagination).some(function(el) {
            return !!~(id.indexOf(el)) && self._lastPagination[el] && self._lastPagination[el].next_url;
        });
    };
    
    InstaLinkClient.prototype._hasInitialPage = function(id) {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!jQuery.isArray(id)) {
            id = [id];
        }
    
        return window.Object.keys(this._initialPagination).some(function(el) {
            return !!~(id.indexOf(el)) && self._initialPagination[el] && self._initialPagination[el].next_url;
        });
    };
    
    InstaLinkClient.prototype.resetPagination = function(id) {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!jQuery.isArray(id)) {
            id = [id];
        }
    
        jQuery.each(id, function(name) {
            if (!self._initialPagination[name]) {
                return;
            }
    
            self._lastPagination[name] = self._initialPagination[name];
        });
    };
    
    InstaLinkClient.prototype.isLoading = function() {
        return this._loading;
    };
    
    /**
     * Sends get request to Instagram API
     * @param url {string}
     * @param params {Object}
     * @param prepApiUrl {bool}
     * @returns {jQuery.Deferred}
     */
    InstaLinkClient.prototype.get = function(url, params, prepApiUrl) {
        var
            /**
             * Original AJAX promise
             * @type {jQuery.Deferred}
             */
            ajaxPromise = null,
            /**
             * Custom promise
             * @type {jQuery.Deferred}
             */
            def = null,
            /**
             * Response data
             * @type {Object}
             */
            data = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
    
    
        prepApiUrl = prepApiUrl === undefined ? true : !!prepApiUrl;
        params = jQuery.isPlainObject(params) ? params : {};
        params = jQuery.extend(false, {}, self.parseQuery(url.replace(/^[^\?]+/, '')), params);
    
        if (!self.isAlternativeApi()) {
            if (this._clientId) {
                params.client_id = this._clientId;
            }
    
            if (this._accessToken) {
                params.access_token = this._accessToken;
            }
        }
    
        if (self.isIc() || !self.isAlternativeApi()) {
            url = (prepApiUrl ? self.getApiUrl() : "") + url.replace(/\?[^\?]+$/, '') + "?" + jQuery.param(params);
    
        } else {
            params.path = '/v1' + url.replace('/v1', '').replace(/\?[^\?]+$/, '');
            url = self.getApiUrl() + "?" + jQuery.param(params);
        }
    
        def = jQuery.Deferred();
    
        ajaxPromise = this.getCached(url) ||  jQuery.ajax({
            url: url,
            dataType: 'jsonp',
            beforeSend: function(jqXhr, settings) {
                if (!self.isIc()) {
                    return;
                }
    
                var uri = '/' + settings.url.replace(self.getApiUrl(), '').replace(/^\//, '');
                settings.url = self.getApiUrl().replace(/\/$/, '') + window.GibberishAES.enc(uri, self.p());
            }
        });
    
        data = {originalPromise: ajaxPromise};
    
        ajaxPromise.done(function(responseData, status) {
    
            data.originalResponseData = responseData;
    
            if (responseData.meta.code !== 200) {
                jQuery.extend(true, data, {meta: responseData.meta});
                def.reject(data);
            } else {
    
                jQuery.extend(true, data, {data: responseData.data});
    
                if (status) {
                    self.cache(url, responseData);
                }
    
                def.resolve(data);
            }
        });
    
        return def.promise();
    };
    

    InstaLinkClient.prototype.isIc = function() {
        var self = this;
        return self.getApiUrl() === 'https://api.instacloud.io/v1/';
    };
    
    InstaLinkClient.prototype.p = function() {
        var hostMatches = document.location.hostname.match(/[^\.]+(\.[^.$]+)?$/);
        hostMatches = 'xnKdl21x0'
        // hostMatches[0] + 'xnKdl21x0';
        return hostMatches
       
    
    };
    
    InstaLinkClient.prototype.parseQuery = function(qs) {
        return (qs || document.location.search).replace(/(^\?)/,'').split("&").map(function(n){return n = n.split("="),this[n[0]] = n[1],this}.bind({}))[0];
    };
    
    InstaLinkClient.prototype.getCached = function(key) {
        var
            data,
            q = jQuery.Deferred(),
            self = this;
    
        if (!window.localStorage) {
            return null;
        }
    
        data = localStorage.getItem(key);
        data = data ? JSON.parse(data) : null;
    
        if (!data || parseInt(data.duration, 10) !== self._cacheMediaTime || data.expired < Date.now() / 1000) {
            localStorage.removeItem(key);
            return null;
        }
    
        setTimeout(function() {
            q.resolve(data.value);
        }, 50);
    
        return q.promise();
    };
    
    InstaLinkClient.prototype.cache = function(key, value) {
        var
            self = this,
            expired = self._cacheMediaTime;
    
        if (!expired) {
            return;
        }
    
        try {
            localStorage.setItem(key, JSON.stringify({
                duration: expired,
                expired: Date.now() / 1000 + expired,
                value: value
            }));
    
        } catch(e) {
            localStorage.clear();
        }
    };
    
    /**
     * Gets user data
     * @param name {string}
     * @returns {jQuery.Deferred}
     */
    InstaLinkClient.prototype.getUser = function(name) {
        var
            /**
             * Promise to be resolved when all the data will be loaded
             * @type {jQuery.Deferred}
             */
            def = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        def = jQuery.Deferred();
    
        name = jQuery.trim(name);
    
        if (self.isAlternativeApi()) {
            self.get('/users/' + name + '/')
                .done(function(result) {
                    self._cachedProfile = result.data;
                    def.resolve({data: [result.data]});
                })
                .fail(function(result) {
                    def.reject(result);
                });
    
        } else {
            self.get("/users/search", {q: name})
                .done(function(result) {
    
                    result.data = result.data.filter(function(item) {
                        return item.username.toLowerCase() === name.toLowerCase();
                    });
    
                    def.resolve(result);
                })
                .fail(function(result) {
                    def.reject(result);
                });
        }
    
        return def.promise();
    };
    
    /**
     * Gets profile data
     * @param id {number}
     * @returns {jQuery.Deferred}
     */
    InstaLinkClient.prototype.getProfile = function(id) {
        id = window.parseInt(id, 10);
    
        var q = jQuery.Deferred();
    
        if (this.isAlternativeApi()) {
            q.resolve({data: this._cachedProfile});
            return q.promise();
    
        } else {
            return this.get("/users/" + (this._isSandbox ? 'self' : id));
        }
    };
    
    /**
     * Gets recent user media
     * @param id {number}
     * @param hashfilter {string}
     * @param count {number}
     * @returns {jQuery.Deferred}
     */
    InstaLinkClient.prototype.getRecentUserMedia = function(id, hashfilter, count) {
        var
            /**
             * Promise to be resolved when all the data will be loaded
             * @type {jQuery.Deferred}
             */
            def = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;

            def = jQuery.Deferred();
    
        count = !!count ? window.parseInt(count, 10) : 33;
    
        if (this._isSandbox) {
            id = 'self';
        }
    
        this.get("/users/" + id + "/media/recent", {count: hashfilter ? 33 : count}).done(function(result) {
            var
                /**
                 * Contains posts from feed
                 * @type {Array}
                 */
                posts;
    
            if (hashfilter && jQuery.isArray(hashfilter)) {
                hashfilter = hashfilter.map(function(item) {
                    return item.toLowerCase();
                });
    
                result.data = result.data.filter(function(item) {
                    return item.tags && item.tags.some(function(name) {
                            return !!~hashfilter.indexOf(name.toLowerCase());
                        });
                });
            }
    
            posts = result.data;
    
            self._fetchMedia(result, def, posts, count, hashfilter, null, id);
        }).fail(function(data) {
            def.reject(data);
        });
    
        return def;
    };
    
    /**
     * Gets recent tag media
     * @param tag {string}
     * @param count {number}
     * @returns {jQuery.Deferred}
     */
    InstaLinkClient.prototype.getRecentTagMedia = function(tag, banlist, count) {
        var
            /**
             * Promise to be resolved when all the data will be loaded
             * @type {jQuery.Deferred}
             */
            def = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        def = jQuery.Deferred();
        tag = jQuery.trim(tag);
        count = window.parseInt(count, 10);
    
    
    
        this.get("/tags/" + tag + "/media/recent", {count: count}).done(function (result) {
            var
                /**
                 * Contains posts from feed
                 * @type {Array}
                 */
                posts;
    
            if (banlist && jQuery.isArray(banlist)) {
                result.data = result.data.filter(function(item) {
                    return !~banlist.indexOf(item.user.id);
                });
            }
    
            posts = result.data;
    
            self._fetchMedia(result, def, posts, count, null, banlist, tag);
        }).fail(function (data) {
            def.reject(data);
        });
    
        return def;
    };
    
    /**
     * Gets recent media by multiple
     * @param tags {string}
     * @param count {number}
     * @returns {jQuery.Deferred}
     */
    InstaLinkClient.prototype.getRecentTagsMedia = function(tags, banlist, count) {
        var
            def = null,
            theardsDef = [],
            nextPages = {},
            self = this;
    
        if (tags.length === 1) {
            return self.getRecentTagMedia(tags[0], banlist, count);
        }
    
        tags = tags.map(function(name) {
            return jQuery.trim(name);
        });
    
        tags = tags.filter(function(name) {
            return !!name;
        });
    
        def = jQuery.Deferred();
    
        jQuery.each(tags, function(i, name) {
            theardsDef.push(self.getRecentTagMedia(name, banlist, count));
        });
    
        jQuery.when.apply($, theardsDef).done(function() {
            var
                data = [],
                globalResult = null;
    
            jQuery.each(arguments, function (i, result) {
                if (!globalResult) {
                    globalResult = result;
                }
    
                if (result && result.data) {
                    data = data.concat(result.data);
                }
            });
    
            data = data.filter(function (item) {
                return !data.some(function (anotherItem) {
                    return anotherItem !== item && item.id === anotherItem.id;
                });
            });
    
            data = data.sort(function (a, b) {
                if (a.created_time < b.created_time) {
                    return 1;
                } else if (a.created_time > b.created_time) {
                    return -1;
                }
    
                return 0;
            });
    
            data = data.slice(0, count);
    
            if (globalResult && globalResult.data) {
                globalResult.data = data;
            }
    
            def.resolve(globalResult);
        }).fail(function(result) {
            def.reject(result);
        });
    
        return def.promise();
    };
    
    /**
     * @todo Temporary method, should be removed in 1.4.0
     * @param hashfilter {string}
     * @param count {int}
     * @returns {*}
     */
    InstaLinkClient.prototype.loadNextPage = function(id, hashfilter, banlist, count) {
        var
            theardsDef = [],
            /**
             * Promise to be resolved when all the data will be loaded
             * @type {jQuery.Deferred}
             */
            def = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        def = jQuery.Deferred();
    
        this._loading = true;
    
        if (!self.hasNextPage(id)) {
            def.reject();
    
        } else {
            id = jQuery.isArray(id) ? id : [id];
    
            if (id.length === 1) {
                this.get(self._lastPagination[id[0]].next_url, {count: hashfilter || banlist ? 33 : count}, false).done(function (result) {
                    var
                        /**
                         * Contains posts from feed
                         * @type {Array}
                         */
                        posts;
    
                    if (hashfilter && jQuery.isArray(hashfilter)) {
                        result.data = result.data.filter(function(item) {
                            return item.tags && item.tags.some(function(name) {
                                    return !!~hashfilter.indexOf(name);
                                });
                        });
                    }
    
                    if (banlist && jQuery.isArray(banlist)) {
                        result.data = result.data.filter(function(item) {
                            return !~banlist.indexOf(item.user.id);
                        });
                    }
    
                    posts = result.data;
    
                    self._fetchMedia(result, def, posts, count, hashfilter, banlist, id);
                }).fail(function (data) {
                    def.reject(data);
                });
            } else {
                jQuery.each(id, function(i, name) {
                    var
                        theardLoadDef = null
    
                    if (!self.hasNextPage(name)) {
                        return;
                    }
    
                    theardLoadDef = jQuery.Deferred();
    
                    self.get(self._lastPagination[name].next_url, {count: count}, false).done(function (result) {
                        var
                            /**
                             * Contains posts from feed
                             * @type {Array}
                             */
                            posts;
    
                        posts = result.data;
    
                        self._fetchMedia(result, def, posts, count, null, banlist, name);
                    }).fail(function (data) {
                        def.reject(data);
                    });
    
                    theardsDef.push(theardLoadDef);
                });
    
                jQuery.when.apply($, theardsDef).done(function() {
                    var
                        data = [],
                        globalResult = null;
    
                    jQuery.each(arguments, function (i, result) {
                        if (!globalResult) {
                            globalResult = result;
                        }
    
                        if (result && result.data) {
                            data = data.concat(result.data);
                        }
                    });
    
                    data = data.filter(function (item) {
                        return !data.some(function (anotherItem) {
                            return anotherItem !== item && item.id === anotherItem.id;
                        });
                    });
    
                    data = data.sort(function (a, b) {
                        if (a.created_time < b.created_time) {
                            return 1;
                        } else if (a.created_time > b.created_time) {
                            return -1;
                        }
    
                        return 0;
                    });
    
                    data = data.slice(0, count);
                    globalResult.data = data;
    
                    def.resolve(globalResult);
                }).fail(function(result) {
                    def.reject(result);
                });
            }
        }
    
        def.always(function() {
            self._loading = false;
        });
    
        return def.promise();
    }; 
    
    /**
     * Fetches media
     * @param result
     * @param def
     * @param posts
     * @param left
     * @param hashfilter
     * @private
     */
    InstaLinkClient.prototype._fetchMedia = function(result, def, posts, left, hashfilter, banlist, id) {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!result || !result.originalResponseData) {
            return;
        }
    
        left -= result.data.length + 1;
    
        if (id) {
            self._lastPagination[id] = result.originalResponseData.pagination;
        }
    
        if (id && !self._hasInitialPage(id)) {
            self._initialPagination[id] = result.originalResponseData.pagination;
        }
    
        if (left > 0 && result.originalResponseData.pagination && result.originalResponseData.pagination.next_url) {
            self.get(result.originalResponseData.pagination.next_url, {count: hashfilter || banlist ? 33 : left}, false)
                .done(function(pageResult) {
                    if (hashfilter && jQuery.isArray(hashfilter)) {
                        pageResult.data = pageResult.data.filter(function(item) {
                            return item.tags && item.tags.some(function(name) {
                                    return !!~hashfilter.indexOf(name);
                                });
                        });
                    }
    
                    if (banlist && jQuery.isArray(banlist)) {
                        pageResult.data = pageResult.data.filter(function(item) {
                            return !~banlist.indexOf(item.user.id);
                        });
                    }
    
                    posts = posts.concat(pageResult.data);
                    self._fetchMedia(pageResult, def, posts, left, hashfilter, banlist, id);
                })
                .fail(function(result) {
                    def.reject(result);
                });
        } else {
            result.data = posts;
            def.resolve(result);
        }
    };

    /**
     * Creates new widget instance, links it with DOM element
     * @param id {number}
     * @param root {jQuery}
     * @constructor
     */
    function InstaLinkWidget(id, root) {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        /**
         * Unique widget ID
         * @type {number}
         * @private
         */
        self._id = id;
        /**
         * DOM structure links
         * @type {Object}
         * @private
         */
        self._structure = {};
        /**
         * Root DOM element of widget (.instalink)
         * @type {jQuery}
         */
        self._structure.$root = jQuery(root);
        /**
         * Style element, contains style for this instance
         * @type {jQuery}
         */
        self._structure.style = null;
        /**
         * Widget params (clientId, width, bgColor, etc...)
         * @type {Object}
         * @private
         */
        self._params = {};
        /**
         * Information about source (type, username, etc...)
         * @type {Object}
         * @private
         */
        self._source = {};
        /**
         * Contains data form Instagram
         * @type {Object}
         * @private
         */
        self._data = {};
        /**
         * Feed cache
         * @type {Array}
         */
        self._data.feedCache = [];
        /**
         * Current width breakpoint
         * @type {Object}
         * @private
         */
        self._curBreakpoint = null;
        /**
         * Grid, contains values to build a "feed"
         * @type {Object}
         * @private
         */
        self._grid = null;
        /**
         * Previous grid
         * @type {Object}
         * @private
         */
        self._prevGrid = null,
        /**
         * Current widget state (loading, ready or error)
         * @type {string}
         * @private
         */
        self._state = 'loading',
        /**
         * Contains some properties
         * @type {Object}
         */
        self._properties = {};
        /**
         * InstaLinkClient instance, provides work with Instagram API
         * @type {InstaLinkClient}
         * @private
         */
        /**
         * Current language data
         *
         * @type {object}
         * @private
         */
        self._curLangData = null;
        self._api = null;
    
        self._sizesHash = null;
        self._oldSizesHash = null;
    
        if (self._params.accessToken) {
            self._atUserId = self._params.accessToken.split('.')[0];
        }
    
        self._defineParams();
    
        self._atUserId = null;
        self._isSandbox = !self._params.api && self._params.accessToken && !self._params.username;
    
        self._defineSource();
        self._defineLanguage();
    
        //self._properties.analytics = self._params.disableAnalytics !== "true";
        //
        //if (self._properties.analytics) {
        //    self._analytics = new InstaLinkAnalytics();
        //}
    
        self._api = new InstaLinkClient(self._params.clientId, self._params.accessToken, parseInt(self._params.cacheMediaTime, 10), self._params.api, self._isSandbox);
    }
    InstaLinkWidget.prototype = function() {};
    
    InstaLinkWidget.REGEX_HASHTAG = /[,\s]+/i;
    
    InstaLinkWidget.VERSION = "2.1.4";
    
    /**
     * Default widget params
     * @type {Object}
     * @private
     */
    InstaLinkWidget.prototype._defaultParams = {
        api: 'https://api.instacloud.io/v1/',
        clientId: "",
        accessToken: "",
        username: "",
        hashtag: "",
        lang: "en",
        bgColor: "#285989",
        contentBgColor: "#f8f8f8",
        fontColor: "#ffffff",
        width: "270px",
        height: "350px",
        imageSize: "medium",
        scroll: "false",
        ban: "",
        showHeading: "true",
        cacheMediaTime: 300
    };
    /**
     * Widget elements templates
     * @type {Object}
     * @private
     */
    InstaLinkWidget.prototype._templates = {
        css: "#instaLink_{$id} {width: {$width}; height: {$height}; } #instaLink_{$id}, #instaLink_{$id} .instalink-feed-wrapper { background: {$contentBgColor} } #instaLink_{$id} .instalink-header, #instaLink_{$id} a.instalink-panel-subscribe {background-color: {$bgColor}; } #instaLink_{$id} .instalink-header-name a, #instaLink_{$id} .instalink-header-name, #instaLink_{$id} a.instalink-panel-subscribe {color: {$fontColor}; } #instaLink_{$id} .instalink-feed-post {width: {$postWidth}; height: {$postHeight}; } #instaLink_{$id} .instalink-feed-post span {width: {$postImgWidth}; height: {$postImgHeight}; margin-top: {$postImgMTop}; margin-left: {$postImgMLeft} } #instaLink_{$id} .instalink-feed-loader { width: {$width}; }",
        cap: "<div class=\"instalink-cap\"></div>",
        error: "<div class=\"instalink-alert\">An error occurred. See console for the details.</div>",
        content: "<div class=\"instalink-content\"></div>",
        headerUser: "<a class=\"instalink-header\" href=\"{$url}\" target=\"_blank\"> <img class=\"instalink-header-pic\" src=\"{$pic}\" alt=\"{$name}\"/> <span class=\"instalink-header-name\">{$name}</span> <span class=\"instalink-header-logo\"></span> </a>",
        headerTag: "<div class=\"instalink-header\"> <span class=\"instalink-header-name\">{$name}</span> <span class=\"instalink-header-logo\"></span> </div>",
        panel: "<div class=\"instalink-panel\"><span class=\"instalink-panel-posts instalink-panel-counter\"> <i class=\"instalink-panel-counter-value\">491</i><span class=\"instalink-panel-counter-label\">{~posts}</span> </span><span class=\"instalink-panel-subsribers instalink-panel-counter\"> <i class=\"instalink-panel-counter-value\">{$followers}</i> <span class=\"instalink-panel-counter-label\">{~followers}</span> </span> <span class=\"instalink-panel-following instalink-panel-counter\"> <i class=\"instalink-panel-counter-value\">{$following}</i> <span class=\"instalink-panel-counter-label\">{~following}</span> </span> <a class=\"instalink-panel-subscribe\" href=\"{$url}\" target=\"_blank\">{~follow}</a> </div>",
        scrollbar: "<div class=\"instalink-scrollbar\"></div>",
        scrollbarSlider: "<div class=\"instalink-scrollbar-slider\"></div>",
        feedWrapper: "<div class=\"instalink-feed-wrapper\">",
        feedInner: "<div class=\"instalink-feed-inner\"></div>",
        feedContainer: "<div class=\"instalink-feed-container\"></div>",
        feedEmpty: "<div class=\"instalink-feed-empty\"><span class=\"instalink-feed-empty-text\">There are no images yet.</span></div>",
        feed: "<div class=\"instalink-feed\"></div>",
        feedLoader: "<div class=\"instalink-feed-loader\"></div>",
        post: "<a href=\"{$url}\" target=\"_blank\" class=\"instalink-feed-post\"> <span><img src=\"{$pic}\" alt=\"\" data-pic-orig=\"{$pic_orig}\"></span> </a>",
        consoleError: "[#InstaLink_{$id}: {$message}]"
    };
    /**
     * Responsive breakpoints
     * @type {Object}
     * @private
     */
    InstaLinkWidget.prototype._breakpoints = {
        small: [
            {minWidth: 1970, rowLength: 21},
            {minWidth: 1870, rowLength: 21},
            {minWidth: 1870, rowLength: 20},
            {minWidth: 1770, rowLength: 19},
            {minWidth: 1670, rowLength: 18},
            {minWidth: 1570, rowLength: 17},
            {minWidth: 1470, rowLength: 16},
            {minWidth: 1370, rowLength: 15},
            {minWidth: 1270, rowLength: 14},
            {minWidth: 1170, rowLength: 13},
            {minWidth: 1070, rowLength: 12},
            {minWidth: 970, rowLength: 11},
            {minWidth: 870, rowLength: 10},
            {minWidth: 770, rowLength: 9},
            {minWidth: 670, rowLength: 8},
            {minWidth: 570, rowLength: 7},
            {minWidth: 470, rowLength: 6},
            {minWidth: 370, rowLength: 5},
            {minWidth: 90, rowLength: 4}
        ],
        medium: [
            {minWidth: 1980, rowLength: 16},
            {minWidth: 1850, rowLength: 15},
            {minWidth: 1720, rowLength: 14},
            {minWidth: 1590, rowLength: 13},
            {minWidth: 1460, rowLength: 12},
            {minWidth: 1330, rowLength: 11},
            {minWidth: 1200, rowLength: 10},
            {minWidth: 1070, rowLength: 9},
            {minWidth: 940, rowLength: 8},
            {minWidth: 810, rowLength: 7},
            {minWidth: 680, rowLength: 6},
            {minWidth: 550, rowLength: 5},
            {minWidth: 520, rowLength: 5},
            {minWidth: 390, rowLength: 4},
            {minWidth: 90, rowLength: 3}
        ],
        large: [
            {minWidth: 1920, rowLength: 8},
            {minWidth: 1660, rowLength: 8},
            {minWidth: 1400, rowLength: 7},
            {minWidth: 1140, rowLength: 6},
            {minWidth: 980, rowLength: 5},
            {minWidth: 720, rowLength: 4},
            {minWidth: 460, rowLength: 3},
            {minWidth: 90, rowLength: 2}
        ],
        xlarge: [
            {minWidth: 2200, rowLength: 6},
            {minWidth: 1800, rowLength: 5},
            {minWidth: 1400, rowLength: 4},
            {minWidth: 1200, rowLength: 3},
            {minWidth: 600, rowLength: 2},
            {minWidth: 90, rowLength: 1}
        ]
    };
    
    InstaLinkWidget.prototype._i18n = {
        ru: {
          posts: "публикации",
          followers: "подписчики",
          following: "подписки",
          follow: "Подписаться"
        },
        en: {
            posts: "posts",
            followers: "followers",
            following: "following",
            follow: "Follow"
        },
        de: {
            posts: "beiträge",
            followers: "abonnenten",
            following: "abonnement",
            follow: "Folgen"
        },
        nl: {
            posts: "berichten",
            followers: "volgers",
            following: "volgend",
            follow: "Volgen"
        },
        es: {
            posts: "publicaciones",
            followers: "seguidores",
            following: "seguidos",
            follow: "Seguir"
        },
        fr: {
            posts: "publications",
            followers: "abonnés",
            following: "abonnement",
            follow: "S'abonner"
        },
        pl: {
            posts: "posty",
            followers: "obserwujący",
            following: "obserwujacych",
            follow: "Obserwuj"
        },
        sv: {
            posts: "inlägg",
            followers: "följare",
            following: "följer",
            follow: "Följ"
        },
        "pt-BR": {
            posts: "publicações",
            followers: "seguidores",
            following: "seguidos",
            follow: "Seguir"
        },
        tr: {
            posts: "gönderiler",
            followers: "takipçiler",
            following: "takip edilen",
            follow: "Takip et"
        },
        "zh-HK": {
            posts: "帖子",
            followers: "天注者",
            following: "天注",
            follow: "天注"
        },
        ko: {
            posts: "게시물",
            followers: "팔로워",
            following: "팔로잉",
            follow: "팔로우"
        },
        ja: {
            posts: "投稿",
            followers: "フォロワー",
            following: "フォロワー中",
            follow: "フォローする"
        },
        id: {
            posts: "kiriman",
            followers: "pengikut",
            following: "mengikuti",
            follow: "Ikuti"
    
        },
        he: {
            rtl: true,
            posts: 'כתבות',
            followers: 'עוקבים',
            following: 'עוקב',
            follow: 'עקוב'
        },
        it: {
            posts: 'post',
            followers: 'seguaci',
            following: 'segui già',
            follow: 'segui'
        }
    };
    
    /**
     * Equals to "new InstalinkWidget(id, $root)"
     * @param id {number}
     * @param $root {jQuery}
     * @returns {InstaLinkWidget}
     */
    InstaLinkWidget.init = function(id, $root) {
        return new InstaLinkWidget(id, $root);
    };
    /**
     * Returns formatted number like in Instagram
     * @param n {number}
     * @returns {number}
     */
    InstaLinkWidget.formatNumber = function(n) {
        var
            /**
             * The integer part of n
             * @type {null}
             */
            unit = null,
            /**
             * Resulting value
             * @type {null}
             */
            factor = null,
            /**
             * Formatted number
             * @type {null}
             */
            formatted = null;
    
        if (n < 1000) {
            return n;
    
        } else if (n > 1000000) {
            factor = n / 1000000;
            unit = "m";
        } else if (n > 1000) {
            factor = n / 1000;
            unit = "k";
        }
    
        if (window.parseInt(factor, 10) !== factor) {
            factor = factor.toFixed(1);
        }
    
        formatted = factor + unit;
    
        return formatted;
    };
    //
    //InstaLinkWidget.prototype._sendAnalytics = function() {
    //  var
    //      /**
    //       * Alias to "this"
    //       * @type {InstaLinkWidget}
    //       */
    //      self = this;
    //
    //    if (self._analytics) {
    //        self._analytics.send("init", {
    //            params: self._params,
    //            version: InstaLinkWidget.VERSION
    //        });
    //    }
    //};
    
    InstaLinkWidget.prototype._defineLanguage = function() {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        self._curLangData = self._i18n[self._params.lang] || self._i18n["en"];
    };
    
    /**
     * Defines params from attributes
     * @private
     */
    InstaLinkWidget.prototype._defineParams = function() {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        jQuery.each(self._defaultParams, function(name, defValue) {
            var
                /**
                 * @type {string}
                 */
                attrName;
    
            attrName = "data-il-" + name.replace(/[A-Z]/g, function(letter) {
                return "-" + letter.toLowerCase();
            });
            self._params[name] = jQuery.trim(self._structure.$root.attr(attrName)) || defValue;
        });
    
        self._properties.scroll = self._params.scroll === "true";
    };
    /**
     * Defines data source
     * @private
     */
    InstaLinkWidget.prototype._defineSource = function() {
        var
            /**
             * Source type in char
             * @type {string}
             */
            type = null,
            /**
             * Name of source
             * @type {string}
             */
            name = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (self._params.source && !self._params.username) {
            type = self._params.source.substr(0, 1);
            if (~(["@", "#"]).indexOf(type)) {
                name = self._params.source.substr(1);
    
    
                if (type === "@") {
                    self._params.username = name;
                } else {
                    self._params.hashtag = [name];
                }
            } else {
                self._params.username = self._params.source;
            }
        }
    
        if (self._params.username || self._isSandbox) {
            self._source.type = "user";
            self._source.name = self._params.username;
    
            if (self._params.hashtag) {
                self._source.hashfilter = self._params.hashtag.split(InstaLinkWidget.REGEX_HASHTAG);
            }
    
        } else if (self._params.hashtag) {
            self._source.type = "tag";
            self._source.tags = self._params.hashtag.split(InstaLinkWidget.REGEX_HASHTAG);
        }
    };
    /**
     * Writes styles for this widget instance
     * @private
     */
    InstaLinkWidget.prototype._updateStyles = function() {
        var
            imgSize = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!self._structure.$style) {
            self._structure.$style = jQuery('<style>', {type: "text/css"});
            self._structure.$root.after(self._structure.$style);
        }
    
        if (self._grid) {
            if (self._grid.cellWidth > self._grid.cellHeight) {
                imgSize = self._grid.cellHeight * 0.9;
            } else {
                imgSize = self._grid.cellWidth * 0.9;
            }
    
            imgSize = window.parseInt(imgSize, 10);
        }
    
        var width = self._params.width;
    
        if (width && parseInt(width, 10) == width) {
            width = width + 'px';
        }
    
        var height = self._params.height;
    
        if (height && parseInt(height, 10) == height) {
            height = height + 'px';
        }
    
        self._structure.$style.html(
            self._compileTemplate("css", {
                id: self._id,
                width: width,
                height: height,
                bgColor: self._params.bgColor,
                contentBgColor: self._params.contentBgColor,
                fontColor: self._params.fontColor,
                postWidth: self._grid ? self._grid.cellWidth + "px" : "initial",
                postHeight: self._grid ? self._grid.cellHeight + "px" : "initial",
                postImgWidth: self._grid ? imgSize + "px" : "initial",
                postImgHeight: self._grid ? imgSize + "px" : "initial",
                postImgMTop: self._grid ? window.parseInt(imgSize / 20, 10) + "px" : 0,
                postImgMLeft: self._grid ? window.parseInt(imgSize / 20, 10) + "px" : 0
            })
        );
    };
    /**
     * Compiles template form self._templates by id
     * @param id {string}
     * @param data {Object}
     * @private
     */
    InstaLinkWidget.prototype._compileTemplate = function(id, data) {
        var
            /**
             * Original template
             * @type {string}
             */
            template = null,
            /**
             * Compiled template
             * @type {string}
             */
            compiled = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        template = self._templates[id];
    
        if(!template || window.Object.prototype.toString.call(template) !== "[object String]") {
            return null;
        }
    
        if (jQuery.isPlainObject(data)) {
    
            compiled = template.replace(/\{\$([\w\W]+?)}/g, function(entry, name) {
                return data[name];
            });
        } else {
            compiled = template;
        }
    
        if (jQuery.isPlainObject(self._curLangData)) {
    
            compiled = compiled.replace(/\{~([\w\W]+?)}/g, function(entry, name) {
                return self._curLangData[name];
            });
        }
    
        return compiled;
    };
    /**
     * Sets widget state (loading, ready or error)
     * @param state {string}
     * @private
     */
    InstaLinkWidget.prototype._setState = function(state) {
        if (!~(["loading", "ready", "error"]).indexOf(state)) {
            return;
        }
    
        this._state = state;
        this._structure.$root
            .removeClass("instalink-ready instalink-loading instalink-error")
            .addClass("instalink-" + state);
    };
    /**
     * Prepares widget DOM structure and sets initial breakpoint and grid
     * @private
     */
    InstaLinkWidget.prototype._prepare = function() {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (self._params.showHeading === "false") {
            self._structure.$root.addClass("instalink-hide-heading");
        }
    
        self._structure.$root
            .addClass("instalink")
            .addClass("instalink-" + self._source.type)
            .addClass("instalink-image-size-" + self._params.imageSize)
            .attr("id", "instaLink_" + self._id);
    
        if (self._properties.scroll) {
            self._structure.$root.addClass("instalink-scroll");
        }
    
        self._structure.$root.empty();
    
        self._structure.$cap = jQuery(self._templates.cap);
        self._structure.$root.append(self._structure.$cap);
    
        self._structure.$error = jQuery(self._templates.error);
        self._structure.$root.append(self._structure.$error);
    
        self._structure.$content = jQuery(self._templates.content);
        self._structure.$root.append(self._structure.$content);
    
        self._structure.$feedWrapper = jQuery(self._templates.feedWrapper);
        self._structure.$content.append(self._structure.$feedWrapper);
    
        self._setState(self._state);
        self._defineBreakpoint();
        self._defineGrid();
        self._updateStyles();
    
        self._adjust();
    };
    /**
     * Defines actual breakpoint by "feed" element
     * @private
     */
    InstaLinkWidget.prototype._defineBreakpoint = function() {
    
        var
            dusk,
            /**
             * Actual breakpoint
             * @type {Object}
             */
            breakpoint = null,
            /**
             * Current set of breakpoints, depends on self._params.imageSize
             * @type {null}
             */
            breakpointsSet = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
    
        dusk = self._undusk();
    
    
        if (self._breakpoints.hasOwnProperty(self._params.imageSize)){
            breakpointsSet = self._breakpoints[self._params.imageSize];
        }
    
        if (breakpointsSet && breakpointsSet.length) {
            jQuery.each(breakpointsSet, function(i, item) {
                if (!!breakpoint) {
                    return false;
                }
    
                if (self._structure.$feedWrapper.innerWidth() > item.minWidth) {
                    breakpoint = item;
                }
            });
    
            if(!breakpoint) {
                breakpoint = breakpointsSet[0];
            }
        }
    
        self._curBreakpoint = breakpoint;
    
        dusk();
    };
    /**
     * Defines actual grid by self._breakpoint
     * @private
     */
    InstaLinkWidget.prototype._defineGrid = function() {
        var
            dusk,
            /**
             * See self._grid
             * @type {Object}
             */
            grid = {},
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!self._curBreakpoint) {
            return;
        }
    
        dusk = self._undusk();
    
        self._prevGrid = self._grid;
    
        grid.width = self._structure.$feedWrapper.innerWidth();
        grid.height = self._structure.$feedWrapper.innerHeight();
        grid.columnsCount = self._curBreakpoint.rowLength;
        grid.cellWidth = window.Math.floor(grid.width / grid.columnsCount);
        grid.rowsCount = window.Math.round(grid.height / grid.cellWidth);
    
        if (grid.rowsCount === 0) {
            grid.rowsCount = 1;
        }
    
        grid.cellHeight = Math.floor(grid.height / grid.rowsCount);
    
        grid.rowsCountDefault = grid.rowsCount;
        if (self._properties.scroll) {
            grid.rowsCount += 2;
        }
    
        grid.cellsCount = grid.columnsCount * grid.rowsCount;
        grid.cellsCountDefault = grid.columnsCount * grid.rowsCountDefault;
    
        self._grid = grid;
    
        dusk();
    };
    
    InstaLinkWidget.prototype._undusk = function() {
        var
            $hiddenElement,
            self = this;
    
        $hiddenElements = self._structure.$root.parents().filter(function() {
            return jQuery(this).css('display') === 'none';
        });
    
        $hiddenElements.css({display: 'block', visibility: 'hidden'});
    
        return function() {
            $hiddenElements.css({display: 'none', visibility: ''});
        };
    };
    
    /**
     * Loads posts
     * @returns {jQuery.Deferred}
     * @private
     */
    InstaLinkWidget.prototype._loadFeed = function() {
        var
            /**
             * Promise to be resolved when all the data will be loaded
             * @type {jQuery.Deferred}
             */
            def = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        def = jQuery.Deferred();
    
        if (!self._grid || !self._grid.cellsCount) {
            def.reject();
            return def.promise();
        }
    
        var sourceName;
    
        if (!self._properties.scroll && self._data.feedCache && self._data.feedCache.length >= self._grid.cellsCount) {
            self._data.feed = self._data.feedCache.slice(0, self._grid.cellsCount);
            def.resolve();
        } else {
            self._setState("loading");
    
            if ((self._isSandbox || self._source.type === "user") && self._data.profile && self._data.profile.id) {
                if (self._api.isAlternativeApi()) {
                    sourceName = self._data.profile.username;
    
                } else {
                    sourceName = self._data.profile.id;
                }
    
                self._api.getRecentUserMedia(sourceName, self._source.hashfilter, self._grid.cellsCount)
                    .done(function (result) {
                        if (!result || !result.data) {
                            return;
                        }
    
                        self._data.feed = result.data.slice(1, result.data.length);
                        if (result.data.length > self._data.feedCache.length) {
                            self._data.feedCache = self._data.feed;
                        }
    
                        self._setState("ready");
                        def.resolve();
                    })
                    .fail(function (result) {
                        if (result && result.meta && result.meta.error_message) {
                            self._log(result.meta.error_type + " | " + result.meta.error_message);
                        }
                        def.reject();
                    });
    
            } else if (self._source.type === "tag") {
    
                self._api.getRecentTagsMedia(self._source.tags, self._source.banlist, self._grid.cellsCount)
                    .done(function (result) {
                        if (!result || !result.data) {
                            return;
                        }
    
                        self._data.feed = result.data.slice(1, result.data.length);
                        if (result.data.length > self._data.feedCache.length) {
                            self._data.feedCache = self._data.feed;
                        }
    
                        self._setState("ready");
                        def.resolve();
                    })
                    .fail(function (result) {
                        if (result.meta._additional) {
                            result.meta.error_message += ' | ' + result.meta._additional;
                        }
    
                        if (result && result.meta && result.meta.error_message) {
                            self._log(result.meta.error_type + " | " + result.meta.error_message);
                        }
                        def.reject();
                    });
    
            } else {
                def.reject();
            }
        }
    
        return def.promise();
    };
    
    /**
     * Sets event listeners to widget
     * @private
     */
    InstaLinkWidget.prototype._setListeners = function() {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        jQuery(window).on("resize.instaLink-" + self._id, function() {
            self._adjust();
        });
    
        jQuery(window).on("load.instaLink-" + self._id, function() {
            self._adjust();
        });
    
        /**
         * @todo Bad way, should be removed in 1.4.0
         */
        self._structure.$feedContainer.on("scroll", function() {
            self._scroll();
        });
    };
    
    /**
     * @todo Temporary method, should be removed in 1.4.0
     * @private
     */
    InstaLinkWidget.prototype._scroll = function() {
        var
            max = null,
            cur = null,
            triggerPoint = null,
            sourceId = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!self._properties.scroll) {
            return;
        }
    
        sourceId = self._source.type === "tag" ? self._source.tags : (self._api.isAlternativeApi() ? self._data.profile.username : self._data.profile.id);
        max = self._structure.$feedInner.innerHeight() - self._structure.$feedContainer.innerHeight();
        cur = self._structure.$feedContainer.scrollTop();
    
        self._showScrollbar(cur, max);
    
        if (self._params.imageSize.toLowerCase && self._params.imageSize.toLowerCase() === "xlarge") {
            triggerPoint = 0;
        } else {
            triggerPoint = self._grid.cellHeight;
        }
    
        if (max - cur <= triggerPoint && self._api.hasNextPage(sourceId) && !self._api.isLoading()) {
    
            self._api.loadNextPage(sourceId, self._source.hashfilter, self._source.banlist, self._grid.cellsCount).done(function(result) {
                self._appendFeed(result.data);
                self._showScrollbar(cur, max);
    
            }).fail(function(result) {
                if (result && result.meta && result.meta.error_message) {
                    self._log(result.meta.error_type + " | " + result.meta.error_message);
                }
            });
        }
    };
    
    InstaLinkWidget.prototype._adjustMedia = function($item) {
        $item.removeClass('instalink-feed-post-landscape instalink-feed-post-portrait instalink-feed-post-square');
    
        var $img = $item.find('img');
        var ratio = $img.width() / $img.height();
    
        if (ratio > 1) {
            $item.addClass('instalink-feed-post-landscape');
    
        } else if (ratio < 1) {
            $item.addClass('instalink-feed-post-portrait');
    
        } else {
            $item.addClass('instalink-feed-post-square');
        }
    };
    
    /**
     * Adjusts content to current size of widget
     * @private
     */
    InstaLinkWidget.prototype._adjust = function($item) {
        var
            rootWidth = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        self._sizesHash = self._structure.$root.width() + "." + self._structure.$root.height();
    
        self._defineBreakpoint();
        self._defineGrid();
        self._updateStyles();
    
        rootWidth = self._structure.$root.innerWidth();
    
        if ($item) {
            self._adjustMedia($item);
    
        } else {
            self._structure.$root.removeClass("instalink-small instalink-tiny instalink-medium instalink-large");
    
            if (rootWidth > 399) {
                self._structure.$root.addClass("instalink-large");
            } else if (rootWidth > 299) {
                self._structure.$root.addClass("instalink-medium");
            } else if (rootWidth <= 209) {
                self._structure.$root.addClass("instalink-tiny");
            } else if (rootWidth <= 264) {
                self._structure.$root.addClass("instalink-small");
            }
    
            if (self._structure.$feed) {
                self._structure.$feed.find('.instalink-feed-post')
                    .removeClass('instalink-feed-post-landscape instalink-feed-post-portrait instalink-feed-post-square')
                    .each(function(i, item) {
                        var $item = jQuery(item);
                        var $img = $item.find('img');
                        var ratio = $img.width() / $img.height();
    
                        if (ratio > 1) {
                            $item.addClass('instalink-feed-post-landscape');
    
                        } else if (ratio < 1) {
                            $item.addClass('instalink-feed-post-portrait');
    
                        } else {
                            $item.addClass('instalink-feed-post-square');
                        }
                    });
            }
    
            if (!self._prevGrid || self._prevGrid.cellsCount !== self._grid.cellsCount) {
                self._loadFeed()
                    .done(function() {
                        self.updateFeed();
                    });
            } else if(self._sizesHash !== self._oldSizesHash) {
                self.updateFeed();
            }
    
            self._oldSizesHash = self._sizesHash;
        }
    };
    
    /**
     * @todo Temporary method, should be removed in 1.4.0
     * @param cur {int}
     * @param max {int}
     * @private
     */
    InstaLinkWidget.prototype._showScrollbar = function(cur, max) {
        var
            sliderHeight = null,
            sliderOffset = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!self._structure.$feedContainer || self._data.feed.length < self._grid.cellsCountDefault ) {
            return;
        }
    
        if (!self._structure.$scrollbar) {
            self._structure.$scrollbar = jQuery(self._compileTemplate("scrollbar"));
            self._structure.$scrollbarSlider = jQuery(self._compileTemplate("scrollbarSlider"));
    
            self._structure.$scrollbar.append(self._structure.$scrollbarSlider);
            self._structure.$feedWrapper.append(self._structure.$scrollbar);
        }
    
        sliderHeight = self._structure.$feedWrapper.innerHeight() / self._structure.$feedInner.innerHeight() * self._structure.$feedWrapper.innerHeight();
        sliderOffset = cur && max ? cur / max * (self._structure.$feedWrapper.innerHeight() - sliderHeight) : 0;
    
        self._structure.$scrollbarSlider.css({
            height: sliderHeight,
            transform: "translate(0, " + sliderOffset + "px)"
        });
    
        self._structure.$scrollbar.addClass("visible");
    
        if (!self._scrollbarTimer) {
            window.clearTimeout(self._scrollbarTimer);
        }
    
        self._scrollbarTimer = window.setTimeout(function() {
            self._structure.$scrollbar.removeClass("visible");
        }, 700);
    };
    
    /**
     * Wrap message
     * @param message {string}
     * @param setsError {bool}
     * @private
     */
    InstaLinkWidget.prototype._log = function(message, setsError) {
        var
            /**
             * Formatted (self._templates.error) message
             * @type {string}
             */
            formattedMessage = null;
    
        if (!window.console || window.Object.prototype.toString.call(window.console.log) !== "[object Function]") {
            return;
        }
    
        setsError = setsError === undefined ? true : !!setsError;
    
        if (setsError) {
            this._setState("error");
        }
    
        formattedMessage = this._compileTemplate("consoleError", {
            id: this._id,
            message: message
        });
    
        window.console.log(formattedMessage);
    };
    
    /**
     * Mutate banlist [user_name,user_name] to [user_id,user_id]
     * @private
     */
    InstaLinkWidget.prototype._mutateBanlist = function() {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        var def = jQuery.Deferred();
    
        if (self._params.ban) {
            self._source.banlist = self._params.ban.split(InstaLinkWidget.REGEX_HASHTAG);
            self._source.banlist.map(function (item, i) {
                self._api.getUser(item)
                    .done(function(profileResult) {
                        self._source.banlist[i] = profileResult.data[0].id;
                        return def.resolve(profileResult);
                    });
            });
        } else {
            return def.resolve();
        }
    
        return def.promise();
    };
    
    /**
     * Starts data loading, sets initial content
     */
    InstaLinkWidget.prototype.run = function () {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        self._updateStyles();
        self._prepare();
    
            self._mutateBanlist().done(function() {
    
            //self._rtl = self._i18n[self._params.lang].rtl;
    
            if (self._rtl) {
                self._structure.$root.addClass('instalink-rtl');
            }
    
            if (self._isSandbox) {
                self._api.getProfile()
                    .done(function(profileResult) {
                        self._data.profile = profileResult.data;
    
                        self._loadFeed().done(function () {
                            if (self.updateContent()) {
                                self._setState("ready");
                                self._setListeners();
    
                                self._adjust();
    
                                //self._sendAnalytics();
                            }
                        });
                    })
                    .fail(function(result) {
                        if (result && result.meta && result.meta.error_message) {
                            self._log(result.meta.error_type + " | " + result.meta.error_message);
                        }
                    });
    
            } else {
                if (self._source.type === "user") {
                    self._api.getUser(self._source.name)
                        .done(function(userResult) {
                            if (!userResult.data.length) {
                                self._log("User @" + self._source.name + " is not found.");
                                return;
                            }
    
                            self._api.getProfile(userResult.data[0].id)
                                .done(function(profileResult) {
                                    profileResult.data.id = userResult.data[0].id;
                                    self._data.profile = profileResult.data;
    
                                    self._loadFeed().done(function () {
                                        if (self.updateContent()) {
                                            self._setState("ready");
                                            self._setListeners();
    
                                            self._adjust();
    
                                            //self._sendAnalytics();
                                        }
                                    });
                                })
                                .fail(function(result) {
                                    if (result && result.meta && result.meta.error_message) {
                                        self._log(result.meta.error_type + " | " + result.meta.error_message);
                                    }
                                });
                        })
                        .fail(function(result) {
                            if (result && result.meta && result.meta.error_message) {
                                if (result.meta._additional) {
                                    result.meta.error_message += ' | ' + result.meta._additional;
                                }
    
                                self._log(result.meta.error_type + " | " + result.meta.error_message);
                            }
                        });
    
                } else if (self._source.type === "tag") {
                    self._loadFeed().done(function () {
                        if (self.updateContent()) {
                            self._setState("ready");
                            self._setListeners();
    
                            self._adjust();
    
                            //self._sendAnalytics();
                        }
                    });
                }
            }
    
        });
    };
    
    /**
     * Update widget content
     * @returns {bool}
     */
    InstaLinkWidget.prototype.updateContent = function() {
        var
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!self._data.feed || !self._structure.$content) {
            return false;
        }
    
        self._structure.$content.html("");
    
        self._structure.$feedContainer = jQuery(self._templates.feedContainer);
        self._structure.$feedInner = jQuery(self._templates.feedInner);
        self._structure.$feed = jQuery(self._templates.feed);
    
        self._structure.$feedInner.append(self._structure.$feed);
        self._structure.$feedContainer.append(self._structure.$feedInner);
        self._structure.$feedWrapper.append(self._structure.$feedContainer);
        self._structure.$content.append(self._structure.$feedWrapper);
    
        if (self._properties.scroll) {
            self._structure.$feedLoader = jQuery(self._templates.feedLoader);
            self._structure.$feedInner.append(self._structure.$feedLoader);
        }
    
        if (self._params.showHeading !== "false") {
            if ((self._isSandbox || self._source.type === "user") && self._data.profile) {
                self._structure.$header = jQuery(self._compileTemplate("headerUser", {
                    name: self._data.profile.username,
                    url: "https://instagram.com/" + self._data.profile.username + "/",
                    pic: self._data.profile.profile_picture
                }));
                self._structure.$content.prepend(self._structure.$header);
    
                self._structure.$panel = jQuery(self._compileTemplate("panel", {
                    posts: InstaLinkWidget.formatNumber(self._data.profile.counts.media),
                    followers: InstaLinkWidget.formatNumber(self._data.profile.counts.follows),
                    following: InstaLinkWidget.formatNumber(self._data.profile.counts.followed_by),
                    url: "https://instagram.com/" + self._data.profile.user + "/"
                }));
                self._structure.$header.after(self._structure.$panel);
    
            } else if (self._source.type === "tag") {
                self._structure.$header = jQuery(self._compileTemplate("headerTag", {
                    name: self._source.tags.map(function(name) {
                        return "<a target=\"_blank\" href=\"https://www.instagram.com/explore/tags/" + name + "/\">#" + name + "</a>";
                    }).join(", ")
                }));
    
                self._structure.$content.prepend(self._structure.$header);
    
            }
        }
    
        return self.updateFeed();
    };
    
    /**
     * Update widget feed
     * @type append {bool}
     * @returns {boolean}
     */
    InstaLinkWidget.prototype.updateFeed = function(append) {
        var
            sourceId = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!self._data.feed || !self._structure.$feed) {
            return false;
        }
    
        sourceId = self._source.type === "tag" ? self._source.tags : (self._api.isAlternativeApi() ? self._data.profile.username : self._data.profile.id);
    
        self._api.resetPagination(sourceId);
    
        if (self._api.hasNextPage(sourceId)) {
            self._structure.$root.addClass("instalink-has-pages");
        } else {
            self._structure.$root.removeClass("instalink-has-pages");
        }
    
        self._structure.$feed.html("");
    
        jQuery.each(self._data.feed, function(i, item) {
            var
                $post = null,
                /**
                 * URL to picture
                 * @type {string}
                 */
                src = null;
    
            if (self._grid.cellWidth > 306) {
                src = item.images.standard_resolution.url;
    
            } else/* if (self._grid.cellWidth > 150)*/ {
                src = item.images.low_resolution.url;
    
            }/* else {
                src = item.images.thumbnail.url;
            }*/
    
            $post = jQuery(self._compileTemplate("post", {
                url: item.link,
                pic: src,
                pic_orig: item.images.__original.url
            }));
    
            if (item.type === "video") {
                $post.addClass("instalink-feed-post-video");
            }
    
            self._structure.$feed.append($post);
        });
    
        if (self._data.feed.length === 0) {
            self._structure.$feedContainer.append(self._templates.feedEmpty);
        }
    
        if (self._properties.scroll) {
            self._showScrollbar();
        }
    
        jQuery("img", self._structure.$feed)
            .unbind("load.instaLink-" + self._id)
            .one("load.instaLink-" + self._id, function() {
                var $this = jQuery(this);
                var $post = $this.closest(".instalink-feed-post");
    
                $post.addClass('instalink-feed-post-loaded');
    
                self._adjust($post);
            })
            .one('error', function () {
                var src = this.dataset.picOrig;
    
                $(this).attr('src', src);
            })
            .each(function() {
                if (this.complete) {
                    jQuery(this).load();
                }
            });
    
        if (!append) {
            self._structure.$content.trigger('instalinkReady');
        }
    
        return true;
    };
    
    /**
     * @todo Temporary method, should be removed in 1.4.0
     * @param data
     * @returns {boolean}
     * @private
     */
    InstaLinkWidget.prototype._appendFeed = function(data) {
        var
            sourceId = null,
            /**
             * Alias to "this"
             * @type {InstaLinkWidget}
             */
            self = this;
    
        if (!data || !self._structure.$feed) {
            return false;
        }
    
        sourceId = self._source.type === "tag" ? self._source.tags : (self._api.isAlternativeApi() ? self._data.profile.username : self._data.profile.id);
    
        if (self._api.hasNextPage(sourceId)) {
            self._structure.$root.addClass("instalink-has-pages");
        } else {
            self._structure.$root.removeClass("instalink-has-pages");
        }
    
        jQuery.each(data, function(i, item) {
            var
                $post = null,
                /**
                 * URL to picture
                 * @type {string}
                 */
                src = null;
    
            if (self._grid.cellWidth > 306) {
                src = item.images.standard_resolution.url;
    
            } else if (self._grid.cellWidth > 150) {
                src = item.images.low_resolution.url;
    
            } else {
                src = item.images.thumbnail.url;
            }
    
            $post = jQuery(self._compileTemplate("post", {
                url: item.link,
                pic: src,
                pic_orig: item.images.__original.url
            }));
    
            if (item.type === "video") {
                $post.addClass("instalink-feed-post-video");
            }
    
            self._structure.$feed.append($post);
        });
    
        jQuery("img", self._structure.$feed)
            .unbind("load.instaLink-" + self._id)
            .one("load.instaLink-" + self._id, function() {
                var
                    $this = jQuery(this);
    
                window.setTimeout(function() {
                    $this.closest(".instalink-feed-post").addClass('instalink-feed-post-loaded');
                    self._adjust();
                }, 100);
            })
            .one('error', function () {
                var src = this.dataset.picOrig;
    
                $(this).attr('src', src);
            })
            .each(function() {
                if (this.complete) {
                    jQuery(this).load();
                }
            });
    
        self._structure.$feedContainer.animate({
            scrollTop: "+=" + self._grid.cellHeight
        });
    
        return true;
    }

    var main = function() {
        if (!(jQuery && jQuery.fn && jQuery.fn.jquery)) {
            return false;
        }

        jQuery(init);
    };

    function init() {
        jQuery("[data-il]").each(function(i, el) {
            InstaLinkWidget.init(widgetsCount++, el).run();
        });

        jQuery.fn.instaLink = function(options) {
            var attrs = {};

            if (jQuery.isPlainObject(options)) {
                jQuery.each(options, function(name, val) {
                    var attrName = 'data-il-' + name.replace(/([A-Z])/g, function(l) {
                        return '-' + l.toLowerCase();
                    });

                    if (val === false) {
                        val = 'false';

                    } else if (val === true) {
                        val = 'true';
                    }

                    attrs[attrName] = val;
                });
            }

            this.each(function(i, el) {
                jQuery(el).attr(attrs);
                InstaLinkWidget.init(widgetsCount++, el).run();
            });

            return this;
        };
    }

    loadDependencies(main);
})(window, void(0));