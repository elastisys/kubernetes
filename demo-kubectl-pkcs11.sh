#!/usr/bin/env bash

########################
# include the magic
########################
. ./demo-magic.sh


########################
# Configure the options
########################

#
# speed at which to simulate typing. bigger num = faster
#
# TYPE_SPEED=20

# hide the evidence
clear

#pe "minikube delete"
#
#pe "minikube start"
#

# Save keys produced by minikube
if [ -e $HOME/.minikube/client.key ]; then
    cp $HOME/.minikube/client.key $HOME/.minikube/orig-client.key
fi
if [ -e $HOME/.minikube/client.crt ]; then
    cp $HOME/.minikube/client.crt $HOME/.minikube/orig-client.crt
fi

# Restore client key and certificate
cp $HOME/.minikube/orig-client.crt $HOME/.minikube/client.crt
cp $HOME/.minikube/orig-client.key $HOME/.minikube/client.key

kubectl config unset users.minikube > /dev/null
kubectl config set-credentials minikube \
    --client-certificate=$HOME/.minikube/client.crt \
    --client-key=$HOME/.minikube/client.key > /dev/null

pe "kubectl get pods -n kube-system"

pe "cat ~/.kube/config"

pe "cat ~/.minikube/client.key"

pe "ykman piv import-key 9c ~/.minikube/client.key"
pe "ykman piv import-certificate 9c ~/.minikube/client.crt"
pe "wipe -f ~/.minikube/client.*"
pe "kubectl get pods -n kube-system"

pe "kubectl config unset users.minikube"
pe "kubectl config set-credentials minikube --auth-provider=externalSigner --auth-provider-arg=pathSocket=$XDG_RUNTIME_DIR/externalsigner.sock,pathLib=/usr/local/lib/libykcs11.so,slotId=0,objectId=2"
pe "cat ~/.kube/config"
pe "kubectl get pods -n kube-system"

pe "# Let's try without the YubiKey now"
pe "kubectl get pods -n kube-system"
pe ""
