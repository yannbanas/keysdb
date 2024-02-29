
def write_yaml(data_dict, file_path):
    """
    Écrit les données YAML dans un fichier.

    Args:
        data_dict (dict): Un dictionnaire contenant les données à écrire dans le fichier YAML.
        file_path (str): Le chemin du fichier YAML.
    """
    with open(file_path, 'w') as file:
        for key, value in data_dict.items():
            file.write(f"{key}: {value}\n")

def load_yaml(file_path):
    """
    Charge les données YAML à partir d'un fichier.

    Args:
        file_path (str): Le chemin du fichier YAML.

    Returns:
        dict: Les données chargées depuis le fichier YAML.
    """
    data = {}
    with open(file_path, 'r') as file:
        for line in file:
            key, value = line.strip().split(": ", 1)
            data[key] = value
    return data
