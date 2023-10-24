from math_utils.galois import multiple_table

cut = [
    (0b1111000000000000, 12),
    (0b0000111100000000, 8),
    (0b0000000011110000, 4),
    (0b0000000000001111, 0),
]

back_16 = 0b1111111111111111

RCON = [
    0b10000000,
    0b00110000
]


def text16bit_to_nibble_matrix(bit_16):
    """
        将16位数据划分为半字节矩阵
    """
    return [
        [(bit_16&cut[0][0]) >> cut[0][1], (bit_16&cut[1][0]) >> cut[1][1]],
        [(bit_16&cut[2][0]) >> cut[2][1], (bit_16&cut[3][0]) >> cut[3][1]]
    ]

def nibble_matrix_to_text16bit(matrix) -> int:
    return ((matrix[0][0]) << cut[0][1]) + ((matrix[0][1]) << cut[1][1]) + \
           ((matrix[1][0]) << cut[2][1]) + ((matrix[1][1]) << cut[3][1])

def get_bit_vector(num, bit_width) -> list:
    vector = []
    for i in range(bit_width):
        vector.append(num >> (bit_width-1-i))
    return vector

def vector_to_num(vector, bit_width) -> int:
    num = 0
    for i in range(bit_width):
        num = num << i
        num += vector[i]
    
    return num

class AES:
    """
        所有半字节、字节都是以整数(0~15 or 0~255)或二进制数(0b0010...)形式存储
    """

    def __init__(self) -> None:
        self.rounds = 2
        self.plain_text = ""
        self.bit_width = 16
        self.keys = [0x2D55]
        self.plain_nibbles_groups = []
        self.cipher_nibbles_groups = []

        self.sbox = [
            [9, 4, 0x0A, 0x0B],
            [0x0D, 1, 8, 5],
            [6, 2, 0, 3],
            [0x0C, 0x0E, 0x0F, 7]
        ]
        self.reverse_sbox = [
            [0x0A, 5, 9, 0x0B],
            [1, 7, 8, 0x0F],
            [6, 0, 2, 3],
            [0x0C, 4, 0x0D, 0x0E]
        ]

        self.multi_matrix = [[1, 4],
                             [4, 1]]
        self.reverse_multi_matrix = [[9, 2],
                                     [2, 9]]

    def encrypt(self, bit_16_text):
        """
            加密程序
            bit_16_text: 16位以内的整数
        """
        text_nibbles = text16bit_to_nibble_matrix(bit_16_text)
        nibbles =  self.add_key(text_nibbles, 0)

        for i in range(1, self.rounds):
            nibbles = self.nibble_replace(nibbles, self.sbox)
            nibbles = self.shift_row(nibbles)
            nibbles = self.mix_col(nibbles, self.multi_matrix)
            nibbles = self.add_key(nibbles, i)
        
        nibbles = self.nibble_replace(nibbles, self.sbox)
        nibbles = self.shift_row(nibbles)
        nibbles = self.add_key(nibbles, self.rounds)

        return nibble_matrix_to_text16bit(nibbles)

    def decrypt(self, cipher_text):
        """
            解密程序
            cipher_text: 16位以内的整数
        """
        text_nibbles = text16bit_to_nibble_matrix(cipher_text)
        nibbles =  self.add_key(text_nibbles, self.rounds)

        for i in reversed(range(1, self.rounds)):
            nibbles = self.shift_row(nibbles)
            nibbles = self.nibble_replace(nibbles, self.reverse_sbox)
            nibbles = self.add_key(nibbles, i)
            nibbles = self.mix_col(nibbles, self.reverse_multi_matrix)
            
        nibbles = self.shift_row(nibbles)
        nibbles = self.nibble_replace(nibbles, self.reverse_sbox)
        nibbles = self.add_key(nibbles, 0)

        return nibble_matrix_to_text16bit(nibbles)

    def add_key(self, matrix, i) -> list[list[int]]:
        """
            密钥加
        """
        key_nibbles = text16bit_to_nibble_matrix(self.keys[i])
        
        for i in range(len(matrix)):
            for j in range(len(matrix[0])):
                matrix[i][j] = matrix[i][j] ^ key_nibbles[i][j]
        
        return matrix

    def nibble_replace(self, matrix, box) -> list[list[int]]:
        """
            半字节替换
        """
        for i in range(len(matrix)):
            for j in range(len(matrix[0])):
                row = matrix[i][j] >> 2
                col = matrix[i][j] & 0b0011
                matrix[i][j] = box[row][col]

        return matrix

    def shift_row(self, matrix) -> list[list[int]]:
        """
            行位移
        """
        for i in range(len(matrix)):
            matrix[i] = matrix[i][i:]+matrix[i][0:i]

        return matrix

    def mix_col(self, matrix, multi_matrix) -> list[list[int]]:
        """
            列混淆
        """
        new_matrix = []
        for i in range(len(multi_matrix)):
            row = []
            for j in range(len(matrix[0])):
                temp = []
                for k in range(len(matrix[i])):
                    temp.append(multiple_table[multi_matrix[i][k]][matrix[k][j]]);
                for k in range(1, len(temp)):
                    temp[0] = temp[0] ^ temp[k]
                row.append(temp[0])
            new_matrix.append(row)
        
        return new_matrix
    
    def extend_keys(self):
        w_0 = self.keys[0] >> 8
        w_1 = self.keys[0] & 0b11111111

        for i in range(2):
            left_temp = w_1 >> 4
            right_temp = w_1 & 0b00001111
            temp = left_temp

            left_temp = self.sbox[right_temp >> 2][right_temp & 0b0011]
            right_temp = self.sbox[temp >> 2][temp & 0b0011]

            temp = (left_temp << 4) + right_temp

            w_0 = w_0 ^ RCON[i] ^ temp
            w_1 = w_0 ^ w_1

            self.keys.append((w_0 << 8) + w_1)

    def generate_sbox(self):
        """
            sbox、逆sbox 生成...
            好像直接给了sbox,这里就写到生成sbox
        """
        element_bit_width = 4
        left_matrix = [
            [1, 0, 1, 1],
            [1, 1, 0, 1],
            [1, 1, 1, 0],
            [0, 1, 1, 1]
        ]
        col_vector = [1, 0, 0, 1]

        matrix = []
        for i in range(element_bit_width):
            temp = []
            for j in range(element_bit_width):
                temp.append(i+element_bit_width*j)
            matrix.append(temp)

        for i in range(element_bit_width):
            for j in range(element_bit_width):
                ele_bit_vector = get_bit_vector(matrix[i][j], element_bit_width)
                for k in range(element_bit_width):
                    temp = 0
                    for l in range(element_bit_width):
                        temp += left_matrix[k][l]*ele_bit_vector[l]
                    ele_bit_vector[k] = (temp % 2) ^ col_vector[k]
                matrix[i][j] = vector_to_num(ele_bit_vector, element_bit_width)

