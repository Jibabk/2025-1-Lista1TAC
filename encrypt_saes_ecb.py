import base64

#Sbox
S_BOX = {
    0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
    0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
    0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
    0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
}


Rcon = {
    1: 0b10000000,
    2: 0b00110000,
}

GF16_MULTIPLICATION = [
    [0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0],
    [0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF],
    [0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD],
    [0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2],
    [0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9],
    [0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6],
    [0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4],
    [0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB],
    [0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1],
    [0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE],
    [0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC],
    [0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3],
    [0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8],
    [0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7],
    [0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5],
    [0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA],
]


def text_to_blocks(text):
    binary = ''.join(f'{ord(c):08b}' for c in text)
    blocks = [binary[i:i+16] for i in range(0, len(binary), 16)]
    if len(blocks[-1]) < 16:
        blocks[-1] = blocks[-1].ljust(16, '0')  # Preenche com zeros à direita se necessário
    return [
        [[int(block[0:4], 2), int(block[4:8], 2)],
         [int(block[8:12], 2), int(block[12:16], 2)]]
        for block in blocks
    ]

def block_to_string(block):
    return ''.join(f'{n:04b}' for row in block for n in row)

#OK PARA INTEIROS
def sub_nibbles(state):
    for i in range(2):
        for j in range(2):
            state[i][j] = S_BOX[state[i][j]]
    return state

#OK ? PARA INTEIROS
def shift_rows(state):
    aux = state[1][1]
    state[1][1] = state[0][1]
    state[0][1] = aux
    return state

# Função para multiplicar dois elementos em GF(2^4) usando a tabela
def gf16_multiply(a, b):
    return GF16_MULTIPLICATION[a][b]

#OK
def mix_columns(state):
    # Extrai os nibbles dos bytes do estado
    s00 = state[0][0]  # 4 bits menos significativos do primeiro byte
    s10 = state[0][1]      # 4 bits mais significativos do primeiro byte
    s01 = state[1][0]  # 4 bits menos significativos do segundo byte
    s11 = state[1][1]      # 4 bits mais significativos do segundo byte

    # Multiplicação matricial em GF(2^4)
    s00_ = gf16_multiply(s00, 1) ^ gf16_multiply(s10, 4)
    s10_ = gf16_multiply(s00, 4) ^ gf16_multiply(s10, 1)
    s01_ = gf16_multiply(s01, 1) ^ gf16_multiply(s11, 4)
    s11_ = gf16_multiply(s01, 4) ^ gf16_multiply(s11, 1)

    # Combina os nibbles e escreve o resultado de volta no estado
    state[0][0] = s00_    # 4 bits menos significativos do primeiro byte
    state[0][1] = s10_    # 4 bits mais significativos do primeiro byte
    state[1][0] = s01_    # 4 bits menos significativos do segundo byte
    state[1][1] = s11_    # 4 bits mais significativos do segundo byte

    return state

#OK PARA INTEIROS
def add_round_key(state, round_key):
    for i in range(2):
        for j in range(2):
            state[i][j] ^= round_key[i][j]
    return state


#KEY EXPANSION
def gfunc(B, round):
    n0,n1 = (B >> 4,B & 0xF)
    aux = n0
    n0 = S_BOX[n1]
    n1 = S_BOX[aux]
    n0 ^= (Rcon[round] >> 4) & 0xF
    n1 ^= Rcon[round] & 0xF
    return (n0 << 4) | n1
    
    
#KEY EXPANSION
def getNextRoundKey(B0, B1, round):
    B2 = B0 ^ gfunc(B1,round)
    B3 = B2 ^ B1
    return B2, B3

def combine_nibbles(high_nibble, low_nibble):
    # Desloca o nibble mais significativo 4 bits para a esquerda
    word = (high_nibble << 4) | low_nibble
    return word

#KEY EXPANSION OK
def key_expansion(key):
    k0 = [[(key >> 12) & 0xF, (key >> 8) & 0xF],
      [(key >> 4) & 0xF, key & 0xF]]
    word1 = combine_nibbles(k0[0][0], k0[0][1])
    word2 = combine_nibbles(k0[1][0], k0[1][1])
    aux = getNextRoundKey(word1, word2,1)
    k1 = [[(aux[0] >> 4) & 0xF, aux[0] & 0xF],
          [(aux[1] >> 4) & 0xF, aux[1] & 0xF]]
    word1 = combine_nibbles(k1[0][0], k1[0][1])
    word2 = combine_nibbles(k1[1][0], k1[1][1])
    aux = getNextRoundKey(word1, word2,2)
    k2 = [[(aux[0] >> 4) & 0xF, aux[0] & 0xF],
          [(aux[1] >> 4) & 0xF, aux[1] & 0xF]]
    return [k0, k1, k2]

def read_bin(s):
    return int(s, 2)
def bin_to_hex(b):
    return hex(b)[2:]
def string_to_hex(s):
    return bin_to_hex(read_bin(s))

#OK
def encrypt_block(block, round_keys):
    state = add_round_key(block, round_keys[0])
    print(f"\nRound 0: \nEstado após addRoundKey: {state} Em Hex: {string_to_hex(block_to_string(state))} Round Key: {round_keys[0]}\n") #OK

    state = sub_nibbles(state)  #OK
    print("Estado após Sub Nibbles: ", state)
    state = shift_rows(state) #OK
    print("Estado após Shift Rows: ", state)
    state = mix_columns(state) #OK
    print("Estado após Mix Columns: ", state)
    state = add_round_key(state, round_keys[1]) #OK
    print(f"\nRound 1: \nEstado após addRoundKey: {state} Em Hex: {string_to_hex(block_to_string(state))} Round Key: {round_keys[1]}\n") #OK

    state = sub_nibbles(state) #OK
    print("Estado após Sub Nibbles: ", state)
    state = shift_rows(state) #OK
    print("Estado após Shift Rows: ", state)
    state = add_round_key(state, round_keys[2]) #OK
    print(f"\nRound 2: \nEstado após addRoundKey: {state} Em Hex: {string_to_hex(block_to_string(state))} Round Key: {round_keys[2]}\n") #OK

    return state

def encrypt_saes_ecb(text, key):
    key_schedule = key_expansion(key)
    blocks = text_to_blocks(text)
    encrypted = []
    test = []
    for block in blocks:
        test.append(block_to_string(block))
    print("Chave em nibbles:", key_schedule)
    print("Texto em binário:", test)
    print("Texto em Blocos", blocks)

    for block in blocks:
        enc_block = encrypt_block(block, key_schedule)
        encrypted.append(block_to_string(enc_block))

    encrypted_bin = ''.join(encrypted)
    encrypted_hex = hex(int(encrypted_bin, 2))[2:]
    encrypted_b64 = base64.b64encode(int(encrypted_bin, 2).to_bytes((len(encrypted_bin) + 7) // 8, 'big')).decode()

    return encrypted_hex, encrypted_b64, encrypted_bin


message = input("Digite a mensagem: ")
chave = int(input("Digite a chave: "),2) # Exemplo: 0b1010011100111011

cypertext = encrypt_saes_ecb(message, chave)
print("Texto cifrado em hexadecimal:", cypertext[0])
print("Texto cifrado em base64:", cypertext[1])
print("Texto cifrado em binário:", cypertext[2])
