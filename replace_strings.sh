#!/bin/bash

if [ -f /etc/ef_entraid_parameters.conf ]
then
    echo "The file /etc/ef_entraid_parameters.conf was found."
    echo "You can copy that file and continue."
    echo "cp /etc/ef_entraid_parameters.conf replacements_custom.txt"
    echo "Press enter to continue or ctrl+c to quit."
    read p
fi

if [ ! -f replacements_custom.txt ]
then
	echo "You need to copy the replacements.txt file to replacements_custom.txt and do your customization"
	echo "cp replacements.txt replacements_custom.txt"
fi

# Path to the file containing the replacements
REPLACEMENTS_FILE="replacements_custom.txt"

# List of files to perform the replacements in
FILES_TO_REPLACE=("config_files/entraid-ssl.conf" "config_files/ef.auth" "scripts/php/callback.php" "scripts/php/secure_page.php")

# Read the replacements file line by line
while IFS= read -r line
do
  # Extract the placeholder and the replacement value
  PLACEHOLDER=$(echo $line | awk '{print $1}')
  REPLACEMENT=$(echo $line | awk '{print $2}')

  # Perform the replacements in each file
  for FILE in "${FILES_TO_REPLACE[@]}"
  do
    sed -i "s/$PLACEHOLDER/$REPLACEMENT/g" $FILE
  done
done < "$REPLACEMENTS_FILE"

for PLACEHOLDER in "##EFAUTHSECRETKEY##" "##EFAUTHNONCE##"
do
    REPLACEMENT=$(openssl rand -hex 16)
    for FILE in "${FILES_TO_REPLACE[@]}"
    do
        sed -i "s/$PLACEHOLDER/$REPLACEMENT/g" $FILE
    done
done

cp -f replacements_custom.txt /etc/ef_entraid_parameters.conf
chmod 640 /etc/ef_entraid_parameters.conf

echo "Replacements complete."
echo "A copy called \"ef_entraid_parameters.conf\" will be stored in /etc/"
