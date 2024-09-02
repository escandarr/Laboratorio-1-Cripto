import sys
import scapy.all as scapy
from termcolor import colored

def decrypt_cesar(ciphertext, shift):
    plaintext = ""
    for char in ciphertext:
        if char.isalpha():
            if char.islower():
                decrypted_char = chr(((ord(char) - ord('a') - shift) % 26) + ord('a'))
            elif char.isupper():
                decrypted_char = chr(((ord(char) - ord('A') - shift) % 26) + ord('A'))
        else:
            decrypted_char = char
        plaintext += decrypted_char
    return plaintext

def load_word_list(file_path):
    with open(file_path, 'r') as file:
        return set(word.strip().lower() for word in file)

def is_english_word(word, word_set):
    return word.lower() in word_set

def main():
    if len(sys.argv) != 3:
        print("Uso: python3 cesar_desencripter.py captura.pcapng diccionario.txt")
        print("Por favor, proporciona la ruta del archivo de captura .pcapng y el archivo de diccionario .txt como argumentos.")
        sys.exit(1)

    pcap_file = sys.argv[1]
    dict_file = sys.argv[2]

    try:
        packets = scapy.rdpcap(pcap_file)
        word_set = load_word_list(dict_file)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    id_to_payloads = {}
    for packet in packets:
        if scapy.ICMP in packet and scapy.Raw in packet:
            id_icmp = packet[scapy.ICMP].id
            payload = packet[scapy.Raw].load[56:]
            if id_icmp in id_to_payloads:
                id_to_payloads[id_icmp].append(payload)
            else:
                id_to_payloads[id_icmp] = [payload]

    best_shift = None
    best_phrase = None
    best_word_count = 0

    possible_phrases = []

    for id_icmp, payloads in id_to_payloads.items():
        combined_payload = b''.join(payloads)
        for shift in range(26):
            decrypted_text = decrypt_cesar(combined_payload.decode(), shift)
            possible_phrases.append(decrypted_text)

    for shift, phrase in enumerate(possible_phrases):
        word_count = sum([is_english_word(word, word_set) for word in phrase.split()])
        if word_count > best_word_count:
            best_shift = shift
            best_phrase = phrase
            best_word_count = word_count

    for shift, phrase in enumerate(possible_phrases):
        if shift == best_shift:
            print(colored(f"{shift}: {phrase}", 'red'))
        else:
            print(f"{shift}: {phrase}")

if __name__ == "__main__":
    main()
