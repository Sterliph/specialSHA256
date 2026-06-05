#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cmath>

using namespace std;

vector<uint32_t> constants = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

string hexs = "0123456789abcdef";

uint32_t rotr32(uint32_t x, int k){
    return (x >> k) | (x << (32-k));
}

uint32_t genSi0(uint32_t x){
    return rotr32(x,7) ^ rotr32(x, 18) ^ (x >> 3);
}

uint32_t genSi1(uint32_t x){
    return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10);
}

uint32_t genS0(uint32_t x){
    return rotr32(x,2) ^ rotr32(x,13) ^ rotr32(x,22);
}

uint32_t genS1(uint32_t x){
    return rotr32(x,6) ^ rotr32(x,11) ^ rotr32(x,25);
}

uint32_t genCH(uint32_t x, uint32_t y, uint32_t z){
    return (x & y) ^ ((~x) & z);
}

uint32_t genMAJ(uint32_t x, uint32_t y, uint32_t z){
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t genT1(uint32_t h, uint32_t s1, uint32_t ch, uint32_t constant, uint32_t word){
    return h + s1 + ch + constant + word;
}

uint32_t genT2(uint32_t s0, uint32_t maj){
    return s0 + maj;
}

vector<uint32_t> BlockSHA256(string blockMessage, vector<uint32_t> &charVariables, uint64_t sizeMessage){

    vector<uint8_t> bytes = {};
    vector<uint8_t> subBytes = {};
    
    //Supplement given block of message
    {
    for (char c : blockMessage){
        bytes.push_back(static_cast<uint8_t>(c));
    }
    if (bytes.size() <= 55){
        bytes.push_back(0x80);
        while (bytes.size() != 56){
            bytes.push_back(0x00);
        }
        for (int i = 7; i >= 0; --i){
            bytes.push_back(static_cast<uint8_t>((sizeMessage >> (i*8)) & 0xFF));
        }
    }else if (bytes.size() < 64){
        bytes.push_back(0x80);
        while (bytes.size() != 64){
            bytes.push_back(0x00);
        }
        while (subBytes.size() != 56){
            subBytes.push_back(0x00);
        }
        for (int i = 7; i >= 0; --i){
            subBytes.push_back(static_cast<uint8_t>((sizeMessage >> (i*8)) & 0xFF));
        }
    }
    }

    vector<uint32_t> chunk = {};
    vector<uint32_t> subChunk = {};

    //Fill chunks
    {
    for (int k = 0; k < 64; ++k){
        if (k < 16){
            chunk.push_back(static_cast<uint32_t>((bytes[chunk.size()*4] << 24) + (bytes[chunk.size()*4 + 1] << 16) + (bytes[chunk.size()*4 + 2] << 8) + bytes[chunk.size()*4 + 3]));
        }else{
            chunk.push_back(chunk[k-16] + genSi0(chunk[k-15]) + chunk[k-7] + genSi1(chunk[k-2]));
        }
    }
    if (subBytes.size() != 0){
        for (int k = 0; k < 64; ++k){
            if (k < 16){
                subChunk.push_back(static_cast<uint32_t>((subBytes[subChunk.size()*4] << 24) + (subBytes[subChunk.size()*4 + 1] << 16) + (subBytes[subChunk.size()*4 + 2] << 8) + subBytes[subChunk.size()*4 + 3]));
            }else{
                subChunk.push_back(subChunk[k-16] + genSi0(subChunk[k-15]) + subChunk[k-7] + genSi1(subChunk[k-2]));
            }
        }
    }
    }

    //Update charVariables
    {
    uint32_t a = charVariables[0];
    uint32_t b = charVariables[1];
    uint32_t c = charVariables[2];
    uint32_t d = charVariables[3];
    uint32_t e = charVariables[4];
    uint32_t f = charVariables[5];
    uint32_t g = charVariables[6];
    uint32_t h = charVariables[7];
    for (int j = 0; j < 64; ++j){
        uint32_t T1 = genT1(h, genS1(e), genCH(e,f,g), constants[j], chunk[j]);
        uint32_t T2 = genT2(genS0(a), genMAJ(a,b,c));
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    charVariables[0] += a;
    charVariables[1] += b;
    charVariables[2] += c;
    charVariables[3] += d;
    charVariables[4] += e;
    charVariables[5] += f;
    charVariables[6] += g;
    charVariables[7] += h;

    if (subChunk.size() != 0){
        uint32_t a = charVariables[0];
        uint32_t b = charVariables[1];
        uint32_t c = charVariables[2];
        uint32_t d = charVariables[3];
        uint32_t e = charVariables[4];
        uint32_t f = charVariables[5];
        uint32_t g = charVariables[6];
        uint32_t h = charVariables[7];
        for (int j = 0; j < 64; ++j){
            uint32_t T1 = genT1(h, genS1(e), genCH(e,f,g), constants[j], subChunk[j]);
            uint32_t T2 = genT2(genS0(a), genMAJ(a,b,c));
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        charVariables[0] += a;
        charVariables[1] += b;
        charVariables[2] += c;
        charVariables[3] += d;
        charVariables[4] += e;
        charVariables[5] += f;
        charVariables[6] += g;
        charVariables[7] += h;
    }
    }

    return charVariables;
}

string hashFromHVariables(vector<uint32_t> &charVariables){
    string hash = "";
    for (uint32_t l : charVariables){
        for (int i = 7; i >= 0; --i){
            hash += hexs[static_cast<int>((l >> 4*i) & 0xF)];
        }
    }   
    return hash;
}

string hashFromFile(string filePath, vector<uint32_t> &charVariables){
    ifstream in;
    char buffer[64] = {};
    string blockMessage;
    int flag = 0; //this mean what we dont go to the case [(size of block) != 64]
    uint64_t sizeMessage = 0;

    in.open(filePath, ios::binary);
    if (!in.is_open()){
        in.close();
        return "Invalid path to file or this file is not exist. Check and retry.";
    }else{
        //function for dividing our message from file
        while (1){
            in.read(buffer, 64);
            if (in.gcount() != 64){
                flag = 1;
                sizeMessage += in.gcount()*8;
                blockMessage = string(buffer, in.gcount());
                charVariables = BlockSHA256(blockMessage, charVariables, sizeMessage);
                break;
            }else{
                blockMessage = string(buffer, in.gcount());
                sizeMessage += 512;
                charVariables = BlockSHA256(blockMessage, charVariables, sizeMessage);
            }
            memset(buffer, 0, sizeof(buffer));
        }
        in.close();
        
        if (!flag){
            charVariables = BlockSHA256("", charVariables, sizeMessage);
        }

        return hashFromHVariables(charVariables);
    }
}

string hashFromString(string valueString, vector<uint32_t> &charVariables){
    
    uint64_t sizeMessage = valueString.length()*8;
    int flag = 0; //this mean what we dont go to the case [(size of block) < 64]

    //combine chunks from string and update charVariables
    while (1){
        if (valueString.length() < 64){
            flag = 1;
            charVariables = BlockSHA256(valueString, charVariables, sizeMessage);
            break;
        }else{
            charVariables = BlockSHA256(valueString.substr(0,64), charVariables, sizeMessage);
            valueString = valueString.erase(0, 64);
        }
    }

    if (!flag){
        charVariables = BlockSHA256("", charVariables, sizeMessage);
    }

    return hashFromHVariables(charVariables);
}

int main(int argc, char* argv[]){
    
    vector<uint32_t> charVariables = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    string valueHash;
    switch(argc){
        case 2:
            if (string(argv[1]) == "--help"){
                cout << "Available commands:" << endl;
                cout << "  --file \"path\"                      : Provide a file path to hash" << endl;
                cout << "  --string \"text\"                    : Provide a plain string to hash" << endl;
                cout << "  --checksum --file \"path\" \"hash\"    : Compare hash of file with expected hash" << endl;
                cout << "  --checksum --string \"text\" \"hash\"  : Compare hash of string with expected hash" << endl;
                cout << "  --help                             : Show this help message";
            }else{
                cout << "Unknown or incomplete command. Use --help." << endl;
            }
            break;
        case 3:
            if (string(argv[1]) == "--file"){
                valueHash = hashFromFile(string(argv[2]), charVariables);
                cout << valueHash << endl;
            }else if (string(argv[1]) == "--string"){
                cout << hashFromString(string(argv[2]), charVariables);
            }else{
                cout << "Invalid command. Use --help.";
            }
            break;
        case 5:
            if (string(argv[1]) == "--checksum"){
                if (string(argv[2]) == "--file"){
                    valueHash = hashFromFile(argv[3], charVariables);
                    if (valueHash != ""){
                        if (valueHash == string(argv[4])){
                            cout << "Hash of file equals given hash.";
                        }else{
                            cout << "Hash of file not equals given hash.";
                        }
                    }
                }else if (string(argv[2]) == "--string"){
                    valueHash = hashFromString(argv[3], charVariables);
                    if (valueHash == string(argv[4])){
                        cout << "Hash of file equals given hash.";
                    }
                }else{
                    cout << "Invalid checksum type. Use --help.";
                }
            }else{
                cout << "Invalid command format for checksum. Use --help.";
            }
            break;
        default:
            cout << "Unknown or unsupported number of arguments. Use --help.";
    }

    return 0;
}
