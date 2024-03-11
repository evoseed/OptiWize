/system script
# removing old scripts if present
:if ([/system script find name=vpn-migration] != "") do={
    /system script remove [find name=vpn-migration]
}
add name=vpn-migration source="\
    \n# Recupero delle credenziali da L2TP\
    \n:local l2tpUser [/interface l2tp-client get [find name=\"l2tp-cloudtik\"] user];\
    \n:local l2tpPass [/interface l2tp-client get [find name=\"l2tp-cloudtik\"] password];\
    \n\
    \n# Creazione interfaccia OpenVPN\
    \n/interface ovpn-client\
    \n# cancello se per caso esiste già l'interfaccia\
    \n:if ([/interface ovpn-client find name=orchestrator] != \"\") do={\
    \n    /interface ovpn-client remove [find name=orchestrator]\
    \n}\
    \nadd name=orchestrator connect-to=vpn.cloudtik.it user=\$l2tpUser password=\$l2tpPass port=1188 disabled=no comment=#orchestrator-autoprovisioning-ovpnclient\
    \n\
    \n# Disabilitazione interfaccia L2TP\
    \n/interface l2tp-client\
    \nset [find name=\"l2tp-cloudtik\"] disabled=yes\
    \n\
    \n# Attesa per 10 secondi\
    \n:delay 10s\
    \n\
    \n# Controllo dello stato dell'interfaccia OpenVPN\
    \n:local ovpnStatus [/interface ovpn-client get [find name=orchestrator] running];\
    \n\
    \n# Se l'OpenVPN non è UP, riattivare L2TP e disattivare OpenVPN\
    \n:if (\$ovpnStatus = false) do={\
    \n    /interface l2tp-client\
    \n    set [find name=\"l2tp-cloudtik\"] disabled=no\
    \n    \
    \n    /interface ovpn-client\
    \n    set [find name=orchestrator] disabled=yes\
    \n}"