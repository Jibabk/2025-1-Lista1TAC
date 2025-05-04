import base64

#Sbox
S_BOX = {
    0x0: 0x9, 0x1: 0x4, 0x2: 0xA, 0x3: 0xB,
    0x4: 0xD, 0x5: 0x1, 0x6: 0x8, 0x7: 0x5,
    0x8: 0x6, 0x9: 0x2, 0xA: 0x0, 0xB: 0x3,
    0xC: 0xC, 0xD: 0xE, 0xE: 0xF, 0xF: 0x7
}

# Rcon
# A tabela Rcon é usada para gerar as chaves de rodada
Rcon = {
    1: 0b10000000,
    2: 0b00110000,
}

# Tabela de multiplicação em GF(2^4)
# A tabela GF16_MULTIPLICATION é uma matriz que representa a multiplicação em GF(2^4)
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

# Função para converter o texto em binário e dividir em blocos de 16 bits
def text_to_block(text):
    binary = ''.join(f'{ord(c):08b}' for c in text)
    block = binary[0:0+16]
    if len(block) < 16:
        block = block.ljust(16, '0')  # Preenche com zeros à direita se necessário
    return [[int(block[0:4], 2), int(block[4:8], 2)],
         [int(block[8:12], 2), int(block[12:16], 2)]]
        
    
# Função para converter o bloco em uma string binária
def block_to_string(block):
    return ''.join(f'{n:04b}' for row in block for n in row)

# Função para substituir os nibbles usando a S-Box
# A função sub_nibbles percorre cada nibble do estado e o substitui pela entrada correspondente na S-Box
def sub_nibbles(state):
    for i in range(2):
        for j in range(2):
            state[i][j] = S_BOX[state[i][j]]
    return state

# Função para realizar a operação de Shift Rows
def shift_rows(state):
    aux = state[1][1]
    state[1][1] = state[0][1]
    state[0][1] = aux 
    return state

# Função para multiplicar dois elementos em GF(2^4) usando a tabela
def gf16_multiply(a, b):
    return GF16_MULTIPLICATION[a][b]


def mix_columns(state):
    # Extrai os nibbles dos bytes do estado
    s00 = state[0][0]  # 4 bits menos significativos do primeiro byte
    s10 = state[0][1]      # 4 bits mais significativos do primeiro byte
    s01 = state[1][0]  # 4 bits menos significativos do segundo byte
    s11 = state[1][1]      # 4 bits mais significativos do segundo byte

    # Multiplicação matricial em GF(2^4)
    # Utiliza a tabela de multiplicação para realizar a operação de Mix Columns
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

# Função para adicionar a chave de rodada ao estado
def add_round_key(state, round_key):
    for i in range(2):
        for j in range(2):
            state[i][j] ^= round_key[i][j] # XOR entre o estado e a chave de rodada
    return state


# Função para gerar a função g(B) usada na expansão da chave
# A função g(B) aplica a S-Box e XOR com o Rcon correspondente
def gfunc(B, round):
    n0,n1 = (B >> 4,B & 0xF)
    aux = n0
    n0 = S_BOX[n1]
    n1 = S_BOX[aux]
    n0 ^= (Rcon[round] >> 4) & 0xF
    n1 ^= Rcon[round] & 0xF
    return (n0 << 4) | n1
    
    
# Gera a próxima chave de rodada a partir da chave anterior e do número da rodada
def getNextRoundKey(B0, B1, round):
    B2 = B0 ^ gfunc(B1,round)
    B3 = B2 ^ B1
    return B2, B3

# Combina dois nibbles (4 bits cada) em um único byte (8 bits)
def combine_nibbles(high_nibble, low_nibble):
    word = (high_nibble << 4) | low_nibble
    return word

# Função para expandir a chave de 16 bits em 3 chaves de rodada de 16 bits
def key_expansion(key):
    # Converte a chave de 16 bits em 4 nibbles
    k0 = [[(key >> 12) & 0xF, (key >> 8) & 0xF],
      [(key >> 4) & 0xF, key & 0xF]]
    word1 = combine_nibbles(k0[0][0], k0[0][1])
    word2 = combine_nibbles(k0[1][0], k0[1][1])
    aux = getNextRoundKey(word1, word2,1)       # Obtem a próxima chave de rodada
    k1 = [[(aux[0] >> 4) & 0xF, aux[0] & 0xF],
          [(aux[1] >> 4) & 0xF, aux[1] & 0xF]]
    word1 = combine_nibbles(k1[0][0], k1[0][1])
    word2 = combine_nibbles(k1[1][0], k1[1][1])
    aux = getNextRoundKey(word1, word2,2)      # Obtem a próxima chave de rodada
    k2 = [[(aux[0] >> 4) & 0xF, aux[0] & 0xF],
          [(aux[1] >> 4) & 0xF, aux[1] & 0xF]] 
    return [k0, k1, k2]

def read_bin(s):
    return int(s, 2)
def bin_to_hex(b):
    return hex(b)[2:]
def string_to_hex(s):
    return bin_to_hex(read_bin(s))


def encrypt_block(block, round_keys):
    state = add_round_key(block, round_keys[0])     # Adiciona a chave de rodada inicial
    print(f"\nRound 0: \nEstado após addRoundKey: {state} Em Hex: {string_to_hex(block_to_string(state))} Round Key: {round_keys[0]}\n") 

    state = sub_nibbles(state)           # Substitui os nibbles usando a S-Box  
    print("Estado após Sub Nibbles: ", state)
    state = shift_rows(state)        # Realiza a operação de Shift Rows
    print("Estado após Shift Rows: ", state)
    state = mix_columns(state)      # Realiza a operação de Mix Columns
    print("Estado após Mix Columns: ", state)
    state = add_round_key(state, round_keys[1])     # Adiciona a chave de rodada 1
    print(f"\nRound 1: \nEstado após addRoundKey: {state} Em Hex: {string_to_hex(block_to_string(state))} Round Key: {round_keys[1]}\n") 

    state = sub_nibbles(state)         # Substitui os nibbles usando a S-Box
    print("Estado após Sub Nibbles: ", state)
    state = shift_rows(state)     # Realiza a operação de Shift Rows
    print("Estado após Shift Rows: ", state)
    state = add_round_key(state, round_keys[2])     # Adiciona a chave de rodada 2
    print(f"\nRound 2: \nEstado após addRoundKey: {state} Em Hex: {string_to_hex(block_to_string(state))} Round Key: {round_keys[2]}\n") 

    return state

def encrypt_saes(text, key):
    key_schedule = key_expansion(key)   # Obtem os round keys
    block = text_to_block(text)         # Converte o texto em binário e o divide em um bloco de 16 bits
    encrypted = []
    print("Chave em nibbles:", key_schedule)
    print("Texto em binário:", block_to_string(block))
    print("Texto em Bloco", block)

    enc_block = encrypt_block(block, key_schedule)  # Cifra o bloco
    encrypted.append(block_to_string(enc_block))    

    encrypted_bin = ''.join(block_to_string(enc_block)) # Converte o bloco cifrado em binário
    encrypted_hex = hex(int(encrypted_bin, 2))[2:]  # Converte o bloco cifrado em hexadecimal
    encrypted_b64 = base64.b64encode(int(encrypted_bin, 2).to_bytes((len(encrypted_bin) + 7) // 8, 'big')).decode() # Converte o bloco cifrado em base64

    return encrypted_hex, encrypted_b64, encrypted_bin
## ----------------------------------- ##

while True:
    try:
        message = input("Digite a mensagem: ")
        binary = ''.join(f'{ord(c):08b}' for c in message)
        if len(binary) > 16:
            print("A mensagem deve ter no máximo 16 bits.")
            continue
        break
    except ValueError:
        print("Entrada inválida. Tente novamente.")
while True:
    try:
        chave = int(input("Digite a chave de 16 bits em binário: "),2) # Exemplo: 0b1010011100111011
        if chave.bit_length() > 16:
            print("A chave deve ter no máximo 16 bits.")
            continue
        break
    except ValueError:
        print("Entrada inválida. Tente novamente.")

cypertext = encrypt_saes(message, chave)
print("Texto cifrado em hexadecimal:", cypertext[0])
print("Texto cifrado em base64:", cypertext[1])
print("Texto cifrado em binário:", cypertext[2])




