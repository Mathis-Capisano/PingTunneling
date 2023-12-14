#!/bin/bash

# Vérifiez si l'utilisateur a les droits d'exécution
if [ "$EUID" -ne 0 ]; then
  echo "Ce script doit être exécuté en tant que superutilisateur (root)."
  exit 1
fi

# Capture des paquets ICMP (type 8 pour les requêtes ping) avec tcpdump en mode continu
tcpdump -i any icmp and icmp[icmptype]=8 -n -l | \
while read line; do
  # Analyser la ligne pour extraire l'adresse IP source
  SOURCE_IP=$(echo "$line" | awk '/IP .* >/{print $3; exit}' | sed 's/\.[0-9]*$//')
  echo ${line}
  # Vérifier si l'adresse IP source est valide
  if [[ "$SOURCE_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    # Répondre au ping
    echo "Réponse au ping depuis $SOURCE_IP"
    ping -c 1 $SOURCE_IP
  else
    echo "Aucun paquet ping capturé ou adresse IP source invalide."
  fi
done
