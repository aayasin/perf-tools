#!/bin/sh
set -e

UPDATE=false

while getopts "u" opt; do
  case ${opt} in
    u)
      UPDATE=true
      ;;
    \? )
      exit 1
      ;;
  esac
done

if $UPDATE; then
  if ! [ -e "uiCA" ]; then
    echo "\033[0;36muiCA is not installed. Remove the -u option when running.\033[0m"
    exit 1
  fi
  cd uiCA
  git pull
  ./setup.sh
else
  if [ -e "uiCA" ]; then
    echo "\033[0;36muiCA is already installed. Add -u option to update.\033[0m"
    exit 0
  fi
  sudo apt-get install gcc python3 python3-pip graphviz
  pip3 install plotly
  git clone https://github.com/andreas-abel/uiCA.git
  cd uiCA
  ./setup.sh
fi
