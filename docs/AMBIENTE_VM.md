# Ambiente: VM de testes RHEL 9

O `enforce --apply` roda **somente** nesta VM. Quem hospeda a VM faz a instalação abaixo; os demais
acessam por SSH e desenvolvem localmente (ver README).

## 1. Criar a VM

- Sistema: RHEL 9 (assinatura gratuita Red Hat Developer, se disponível) **ou** Rocky Linux 9 /
  AlmaLinux 9 (equivalentes binários gratuitos).
- Sugestão: 2 vCPU, 2 a 4 GB de RAM, 20 GB de disco, instalação "Server" mínima.
- Manter **SELinux em enforcing** e **firewalld ativo** (são o alvo das regras).
- Rede: adaptador em modo ponte ou host-only para os colegas alcançarem a porta 22. Se os três
  não estiverem na mesma rede, combinem uma forma de acesso remoto (VPN/túnel) antes de depender disso.
- Crie um usuário comum com `sudo` (grupo `wheel`) e **não** use o root direto.

## 2. Pacotes

```bash
sudo dnf install -y python3 python3-pyyaml git openscap-scanner scap-security-guide
# opcional, para rodar os testes unitários também na VM:
sudo dnf install -y python3-pytest
python3 --version     # esperado: 3.9.x
```

Na VM usa-se o Python do sistema com `python3-pyyaml` do dnf (sem `.venv`, porque o `sudo` não
herda o ambiente virtual).

## 3. Obter o código

```bash
git clone https://github.com/GabFreitasDev/Hardening_RedHat_ATI.git
cd Hardening_RedHat_ATI
python3 -m hardener validar
sudo touch /etc/hardener-vm          # trava de segurança: autoriza o enforce --apply nesta máquina
```

Para atualizar depois: `git pull`.

## 4. Snapshot limpo

Antes de qualquer teste, com a VM recém-instalada e atualizada, tire o snapshot **`base-limpa`**.
Volte a ele para reproduzir o "antes" da demonstração. Tire novos snapshots antes de testar regras de
SSH, PAM ou firewall (podem trancar o acesso).

## 5. Rotina de teste (regras de SSH, PAM e firewall)

1. Abra **uma segunda sessão SSH** e deixe-a aberta; ela é sua saída se algo trancar o acesso.
2. `sudo python3 -m hardener audit`
3. `sudo python3 -m hardener enforce` (dry-run) e leia o que mudaria.
4. `sudo python3 -m hardener enforce --apply`
5. Rode `enforce --apply` de novo: nada deve mudar.
6. `sudo python3 -m hardener rollback` e confirme o estado anterior.

## 6. OpenSCAP (comparação antes/depois)

```bash
# Confirme o arquivo e o perfil na sua distribuição:
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml     # Rocky: ssg-rl9-ds.xml; Alma: ssg-almalinux9-ds.xml
sudo oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_cis \
  --report antes.html /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml
```

Rode antes e depois do `enforce`. Os nomes de arquivo/perfil acima precisam ser confirmados com
`oscap info` na VM (anote o resultado em `VALIDAR_NA_VM.md`).
