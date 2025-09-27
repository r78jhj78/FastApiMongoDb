import requests

def probar_envio(usuario, password):
    url = "https://fastapimongodb-production.up.railway.app/login"

    datos = {
        "username": usuario,
        "username": password
    }

    print("Datos que se enviarán:")
    print(datos)

    try:
        response = requests.post(url, json=datos)
        print(f"Status Code: {response.status_code}")
        print("Respuesta del servidor:")
        try:
            print(response.json())
        except Exception:
            print(response.text)
    except requests.exceptions.RequestException as e:
        print(f"Error en la petición: {e}")

if __name__ == "__main__":
    usuario = input("Usuario: ")
    password = input("Contraseña: ")

    probar_envio(usuario, password)
