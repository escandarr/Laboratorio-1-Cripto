def cifrado_cesar(mensaje, desplazamiento):
    resultado = ""
    for char in mensaje:
        if char.isalpha():  
            base = ord('A') if char.isupper() else ord('a')
            desplazado = (ord(char) - base + desplazamiento) % 26
            resultado += chr(base + desplazado)
        else:
            resultado += char
    return resultado

def descifrar_cesar(mensaje, desplazamiento):
    return cifrado_cesar ((mensaje, -desplazamiento)

def main():
    mensaje = input("Ingrese el mensaje: ")
    desplazamiento = int(input("Ingrese el Rot: "))
    
    mensaje_cifrado = cifrado_cesar ((mensaje, desplazamiento)
    print(f"Mensaje cifrado: {mensaje_cifrado}")
    

if __name__ == "__main__":
    main()
