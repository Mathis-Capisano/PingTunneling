#!/bin/bash

# Vérifiez si l'utilisateur a les droits d'exécution
if [ "$EUID" -ne 0 ]; then
  echo "Ce script doit être exécuté en tant que superutilisateur (root)."
  exit 1
fi

# Capture des paquets ICMP (type 8 pour les requêtes ping) avec tcpdump en mode continu
tcpdump -i any icmp and icmp[icmptype]=8 -n -l | python process_pings.py
