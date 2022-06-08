# -*- coding: utf-8 -*-
"""
Created on Thu Feb 24 16:29:04 2022
Created for 3rd Year Mathematics Project for the 
University of Southampton
@author: maxjn

Implementation of AES in Python
"""

import numpy as np

#Substitution Box
sBox = [[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
         0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76],
        [0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
         0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0],
        [0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
         0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15],
        [0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
         0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75],
        [0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
         0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84],
        [0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
         0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf],
        [0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
         0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8],
        [0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
         0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2],
        [0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
         0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73],
        [0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
         0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb],
        [0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
         0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79],
        [0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
         0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08],
        [0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
         0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a],
        [0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
         0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e],
        [0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
         0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf],
        [0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
         0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]]

#Round constants for key creation
round_constants = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20 ,0x40, 0x80, 0x1B, 0x36] 

#Fixed matrix for mix column step
mix_column_matrix = [[2,1,1,3],
                     [3,2,1,1],
                     [1,3,2,1],
                     [1,1,3,2]]

#Implements XOR with items in '0xAA'/hex as string format
def pythonXOR(item1, item2):
    return hex(int(item1,16) ^ int(item2,16))

#Create new round key based on previous one
def createRoundKey(old_round_key, prev_round_number):
    #Create empty 4x4 array to hold new round key
    new_round_key = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    #Create copy of initial round key for this stage to use later
    copy_old_round_key = old_round_key.copy()
    #Circular byte left shift of column 3 (just right shift 3 times for same effect)
    old_round_key[3] = np.roll(old_round_key[3], 3)
    #SBox substitution of column 3
    new_round_key[3] = subBytes(old_round_key[3])
    #Add Round Constant to column 3
    new_round_key[3][0] = pythonXOR(hex(int(new_round_key[3][0],16)), hex(round_constants[prev_round_number]))

    #Drop '0x' prefix from items in column 3
    for i in range(0,4):
        new_round_key[3][i] = new_round_key[3][i][2:]
    #XOR old column 0 with new column 3, dropping '0x' prefix
    for j in range(len(old_round_key[3])):
        new_round_key[0][j] = pythonXOR(copy_old_round_key[0][j], new_round_key[3][j])[2:]
    
    #XOR columns 1-3 with previous column in new round key, dropping '0x' prefix
    for i in range(1,4):
        for j in range(0,4):
            new_round_key[i][j] = pythonXOR(copy_old_round_key[i][j], new_round_key[i- 1][j])[2:]
    return new_round_key
    
    
#Take in plaintext string for key or text, return 16 byte hex array
def convertToHexArray(data):   
    #Take string of hex characters and return them as pairs
    def chunk(data):
        n = 2
        split_strings = [data[index : index + n] for index in range(0, len(data), n)]
        return (split_strings)  
    #Turn plaintext into hex 
    string_as_hex = data.encode('utf-8').hex()
    #Store as character pairs 
    string_as_hex = chunk(string_as_hex)
    #Create 4x4 array of hex character pairs
    string_as_hex = np.array(string_as_hex).reshape(4,4)
    return (string_as_hex)

    
#Add round key to current cipher text 
def addRoundKey(key_text, cipher_text, zero_or_not):
    #Create empty 4x4 array to hold new cipher text
    new_cipher_text = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    #XOR round key and cipher text 
    for i in range(0,4):
        for j in range(0,4):
            if zero_or_not == 0:
                new_cipher_text[i][j] = pythonXOR(key_text[i][j], cipher_text[i][j])
            else:
                new_cipher_text[j][i] = pythonXOR(key_text[j][i], cipher_text[i][j])
    return new_cipher_text

#Take in a column and use the sBox to look up the new bytes
def subBytes(column):
    #Create empty 1x4 array to hold new column
    new_column = [0,0,0,0]
    for i in range(len(column)):
            #If hex is only 1 digit long i.e. 0-F, add a 0 at the start 
            if len(column[i]) == 2:
                first_digit = column[i][0]
                last_digit = column[i][1]
            else:
                first_digit = '0'
                last_digit = column[i][0]
            #Find place in sBox and return the new hex pair
            new_column[i] = hex(sBox[int(first_digit,16)][int(last_digit,16)])
    return new_column

#Take in cipher text and shift the rows
def shiftRows(old_cipher_text, current_cipher_text):
    old_cipher_text = current_cipher_text.copy()
    #Create empty 4x4 array to hold new round key
    new_rows = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    #Row swap pattern
    row_index = [0,1,2,3]
    #For each column
    for i in range(0,4):
        #Shift row indexes to match the pattern each time
        current_row_index = np.roll(row_index, 4-i)
        #Shift the items in the rows to match the new index
        for j in range(0,4):
            new_rows[i][j] = old_cipher_text[current_row_index[j]][j]
    return(new_rows)
    
#Take in cipher and the mix column matrix, then perform the the linear mixing operation
def mixColumn(cipher_text, mix_column_matrix):
    results_table = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    #for each row in cipher_text
    for i in range(0,4):
        #For each column in mix_column_matrix
        for j in range(0,4):
            results_table [j][i] = hex(mixColMultAll(cipher_text[i], i, j, mix_column_matrix))
    return(results_table)

#Multiplies row with column
def mixColMultAll(row,row_number, col_number, matrix_coeffs):
    #Initialise result of column
    result = 0
    #Calculate mutliple of row and column items
    for i in range(0,4):
        result = result ^ int(mixColMult(row[i], matrix_coeffs[i][col_number]),2)
    return result

#Multiplication step for mixcolumns with two items 
def mixColMult(item, matrix_coeff):
    #Binomial representation of number
    item_binomial = bin(int(item,16))
    #Multiply item binomial representation and matrix coefficient as binary numbers
    if matrix_coeff == 1:
        xor_result = item_binomial
    if matrix_coeff == 2:
        xor_result = (bin(int(item_binomial,2) * 2))
    if matrix_coeff == 3:
        xor_result = bin(int(bin(int(item_binomial,2) * 2),2) ^ int(item_binomial,2))
    #If x^8 in result, then replace with x^4 + x^3 + x + 1
    if len(xor_result) == 11:
        #Remove the leading 1 - x^8
        xor_result = xor_result[:2] + xor_result[(3):]  
        #XOR with x^4 + x^3 + x + 1
        replacement = '0b11011'
        xor_result = bin(int(xor_result,2) ^ int(replacement,2))
    return xor_result

#Round 0
# Take in key and cipher text as 4x4 hex arrays
# XOR key and cipher to get cipher for round 0
#Return the cipher and key for round 0
def zeroRound(hexKey, hexMessage):
    current_cipher_text = addRoundKey(hexKey, hexMessage,0)
    print("Key round 0 " + str(hexKey))
    print("Cipher end of round 0" + str(current_cipher_text))
    return current_cipher_text, hexKey

#All middle rounds
#Take in key and cipher text from previous round
#Generate new round key
#Perfrom subbytes, shiftrows, mixcolumn on cipher text,
#then XOR with new round key
def middleRound(key_text, cipher_text, prev_round_num):
    #Create new round key
    thisKey = createRoundKey(key_text, prev_round_num)
    print("Key Round " + str(prev_round_num + 1))
    print(thisKey)
    #print("Cipher Round " + str(prev_round_num + 1))
    print(cipher_text)
    #Add Round Key
    current_cipher_text = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    old_cipher_text = cipher_text.copy()

    #Subbytes
    for i in range(0,4):
        for j in range(0,4):
            #Trim 0x from hex items in cipher text matrix
            old_cipher_text[i][j] = old_cipher_text[i][j][2:]

    #Perform subBytes on cipher text 
    for i in range(0,4):
        current_cipher_text[i] = subBytes(old_cipher_text[i])

    #ShiftRows
    current_cipher = shiftRows(old_cipher_text, current_cipher_text)

    #MixColumn
    mixed_cipher = mixColumn(current_cipher, mix_column_matrix)
    final_cipher = addRoundKey(thisKey, mixed_cipher, 1)
    print("Cipher at end of round " + str(prev_round_num + 1))
    print(final_cipher)
    return final_cipher, thisKey

#Final round
#Create round key
#Perform subbytes and shiftrows on cipher text, then XOR with round key
def finalRound(key_text, cipher_text, prev_round_num):
    #Create new round key
    thisKey = createRoundKey(key_text, prev_round_num)
    print("Final Key" )
    print(key_text)
    #print("Final Cipher")
    print(cipher_text)
    old_cipher_text = cipher_text.copy()
    current_cipher_text = [[0,0,0,0],[0,0,0,0],[0,0,0,0],[0,0,0,0]]
    #Subbytes
    for i in range(0,4):
        for j in range(0,4):
            #Trim 0x from hex items in cipher text matrix
            old_cipher_text[i][j] = old_cipher_text[i][j][2:]
    #Perform subBytes on cipher text 
    for i in range(0,4):
        current_cipher_text[i] = subBytes(old_cipher_text[i])

    #ShiftRows
    current_cipher = shiftRows(old_cipher_text, current_cipher_text)
    
    final_cipher = addRoundKey(thisKey, current_cipher,0)
    print("Cipher at end of final Round")
    print(final_cipher)
    return final_cipher

def doAES(key_text, cipher_text, middle_round_num):
    print(key_text)
    print(cipher_text)
    cipher, key = zeroRound(key_text, cipher_text)
    for i in range(0,middle_round_num):
        cipher, key = middleRound(key, cipher, i)
    cipher = finalRound(key, cipher, middle_round_num)

#16 byte key
exampleKey = "Tardigrades rock"
#16 byte Message
exampleMessage = "Cute Water Bears"
#Convert key to hex matrix
testKey = convertToHexArray(exampleKey)
#Convert Message to hex matrix
testMessage = convertToHexArray(exampleMessage)

#Run AES-128
doAES(testKey, testMessage, 9)


# New array conversion function for use on the NIST standard key and 
#message, which are already in the form of 32 bit hex strings
#Take in plaintext string for key or text, return 16 byte hex array
def convertTo4x4Array(data):   
    #Take string of hex characters and return them as pairs
    def chunk(data):
        n = 2
        split_strings = [data[index : index + n] for index in range(0, len(data), n)]
        return (split_strings)  
    #Store as character pairs 
    string_as_hex = chunk(data)
    #Create 4x4 array of hex character pairs
    string_as_hex = np.array(string_as_hex).reshape(4,4)
    print(string_as_hex)
    return (string_as_hex)

#NIST standard Key and Message 
standardTestKey = "00000000000000000000000000000000"
standardTestMessage = "6a84867cd77e12ad07ea1be895c53fa3"
#Convert key and message to 4x4 array
stanadardTestKeyArray = convertTo4x4Array(standardTestKey)
standardTestMessageArray = convertTo4x4Array(standardTestMessage)

#Run AES-128
doAES(stanadardTestKeyArray, standardTestMessageArray,9)