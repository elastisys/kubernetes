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

kubectl config unset users.minikube > /dev/null
kubectl config set-credentials minikube \
    --client-certificate=$HOME/.minikube/client.crt \
    --client-key=$HOME/.minikube/client.key > /dev/null

pe "kubectl get pods -n kube-system"

pe "cat ~/.kube/config"

pe "cat ~/.minikube/client.key"

pe "ykman piv import-key 9c ~/.minikube/client.key"
pe "ykman piv import-certificate 9c ~/.minikube/client.crt"

pe "kubectl config unset users.minikube"
pe "cat ~/.kube/config"

pe "kubectl config set-credentials minikube --auth-provider=pkcs11 --auth-provider-arg=path=/usr/local/lib/libykcs11.so,pin=123456,slot-id=0,object-id=2"
pe "cat ~/.kube/config"
pe "kubectl get pods -n kube-system"

pe "# Let's try without the YubiKey now"
pe "kubectl get pods -n kube-system"
pe ""
