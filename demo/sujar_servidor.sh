#!/bin/bash
# ==============================================================================
# ATENÇÃO: NUNCA execute este script em máquina pessoal ou ambiente de produção!
# Este script é EXCLUSIVO para a máquina virtual de testes do RHEL 9 (com snapshot).
# Cria deliberadamente as violações de segurança para testar audit, enforce e rollback.
# Requisito do Escopo ATI - Seção 12 (Trilhas B e C)
# ==============================================================================

set -euo pipefail

echo "[+] Configurando violações de segurança para teste do Hardener ATI..."

# ------------------------------------------------------------------------------
# 1. Dor 6 / Dor 3: PermitRootLogin no SSH e permissões frouxas (SSH-001, SSH-002)
# ------------------------------------------------------------------------------
if [ -f /etc/ssh/sshd_config ]; then
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || true
  chmod 0644 /etc/ssh/sshd_config || true
fi

# ------------------------------------------------------------------------------
# 2. Dor 6: Sudoers com NOPASSWD indevido e comandos amplos (SUDO-001, SUDO-002)
# ------------------------------------------------------------------------------
mkdir -p /etc/sudoers.d
echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-inseguro-ati
echo "estagiario ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/99-inseguro-ati
chmod 0440 /etc/sudoers.d/99-inseguro-ati

# ------------------------------------------------------------------------------
# 3. Dor 6: Segundo usuário com UID 0 (ACC-001)
# ------------------------------------------------------------------------------
if ! grep -q "^toor_demo:" /etc/passwd; then
  if command -v useradd &>/dev/null; then
    useradd -o -u 0 -g 0 -m -d /root/toor_demo -s /bin/bash toor_demo 2>/dev/null || \
    echo "toor_demo:x:0:0:Segundo Root Demo:/root/toor_demo:/bin/bash" >> /etc/passwd
  else
    echo "toor_demo:x:0:0:Segundo Root Demo:/root/toor_demo:/bin/bash" >> /etc/passwd
  fi
fi

# ------------------------------------------------------------------------------
# 4. Dor 5 / Dor 6: Usuário ex_funcionario fora da lista com chave SSH real e no wheel (OFF-001 a OFF-005, SUDO-003)
# ------------------------------------------------------------------------------
if ! id "ex_funcionario" &>/dev/null; then
  useradd -m -s /bin/bash ex_funcionario || true
fi

# Coloca ex_funcionario no grupo wheel (violação para SUDO-003 e OFF-004)
usermod -aG wheel ex_funcionario 2>/dev/null || gpasswd -a ex_funcionario wheel 2>/dev/null || true

# Gera par de chaves SSH real sem senha
mkdir -p /home/ex_funcionario/.ssh
rm -f /root/ex_funcionario_demo_key /root/ex_funcionario_demo_key.pub
ssh-keygen -t ed25519 -N "" -f /root/ex_funcionario_demo_key -C "ex_funcionario@demo-ati" >/dev/null 2>&1 || \
ssh-keygen -t rsa -b 2048 -N "" -f /root/ex_funcionario_demo_key -C "ex_funcionario@demo-ati" >/dev/null 2>&1

if [ -f /root/ex_funcionario_demo_key.pub ]; then
  cat /root/ex_funcionario_demo_key.pub > /home/ex_funcionario/.ssh/authorized_keys
  chmod 700 /home/ex_funcionario/.ssh
  chmod 600 /home/ex_funcionario/.ssh/authorized_keys
  chown -R ex_funcionario:ex_funcionario /home/ex_funcionario/.ssh 2>/dev/null || true
  chmod 600 /root/ex_funcionario_demo_key
fi

# ------------------------------------------------------------------------------
# 5. Dor 6: Permissões de /etc/shadow frouxas (PERM-003)
# ------------------------------------------------------------------------------
if [ -f /etc/shadow ]; then
  chmod 0644 /etc/shadow || true
fi

# ------------------------------------------------------------------------------
# 6. Dor 6: Binário com bit SUID fora da baseline (PERM-001)
# ------------------------------------------------------------------------------
mkdir -p /usr/local/bin
if [ -f /usr/bin/id ]; then
  cp -f /usr/bin/id /usr/local/bin/suid_teste || true
elif [ -f /bin/echo ]; then
  cp -f /bin/echo /usr/local/bin/suid_teste || true
fi
if [ -f /usr/local/bin/suid_teste ]; then
  chmod 4755 /usr/local/bin/suid_teste || true
fi

# ------------------------------------------------------------------------------
# 7. Dor 6: Afrouxar faillock e pwquality (PAM-001, PAM-001b, PAM-002)
# ------------------------------------------------------------------------------
mkdir -p /etc/security
if [ -f /etc/security/faillock.conf ]; then
  sed -i '/^deny[[:space:]]*=/d' /etc/security/faillock.conf || true
  sed -i '/^unlock_time[[:space:]]*=/d' /etc/security/faillock.conf || true
  echo "deny = 0" >> /etc/security/faillock.conf
  echo "unlock_time = 0" >> /etc/security/faillock.conf
else
  echo "deny = 0" > /etc/security/faillock.conf
  echo "unlock_time = 0" >> /etc/security/faillock.conf
fi

if [ -f /etc/security/pwquality.conf ]; then
  sed -i '/^minlen[[:space:]]*=/d' /etc/security/pwquality.conf || true
  echo "minlen = 6" >> /etc/security/pwquality.conf
else
  echo "minlen = 6" > /etc/security/pwquality.conf
fi

# ------------------------------------------------------------------------------
# 8. Dor 6: UMASK frouxo em /etc/login.defs (ACC-002)
# ------------------------------------------------------------------------------
if [ -f /etc/login.defs ]; then
  sed -i 's/^UMASK.*/UMASK 022/' /etc/login.defs || true
  grep -q "^UMASK" /etc/login.defs || echo "UMASK 022" >> /etc/login.defs
else
  echo "UMASK 022" > /etc/login.defs
fi

# ------------------------------------------------------------------------------
# 9. Dor 1: SELinux em modo Permissive (se selinux estiver ativo)
# ------------------------------------------------------------------------------
if command -v setenforce &>/dev/null; then
  setenforce 0 || true
fi
if [ -f /etc/selinux/config ]; then
  sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config || true
fi

# ------------------------------------------------------------------------------
# 10. Dor 2: Diretório de uploads inseguro com permissão de execução
# ------------------------------------------------------------------------------
mkdir -p /var/www/uploads
chmod 0777 /var/www/uploads
printf '#!/bin/bash\necho "Executavel malicioso"\n' > /var/www/uploads/shell.sh
chmod +x /var/www/uploads/shell.sh

# ------------------------------------------------------------------------------
# 11. Dor 3: Desativar proteções de rede do kernel no sysctl
# ------------------------------------------------------------------------------
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv4.conf.all.accept_redirects=1 2>/dev/null || true
sysctl -w kernel.randomize_va_space=0 2>/dev/null || true

# ------------------------------------------------------------------------------
# 12. Checagem do marcador de VM (trava de segurança: criada manualmente pelo operador)
# ------------------------------------------------------------------------------
if [ ! -f /etc/hardener-vm ]; then
  echo ""
  echo "[AVISO] /etc/hardener-vm NÃO encontrado no sistema!"
  echo "        Lembre-se de criá-lo manualmente na VM antes de executar 'enforce --apply':"
  echo "        sudo touch /etc/hardener-vm"
fi

echo ""
echo "=============================================================================="
echo "[OK] Servidor RHEL 9 preparado com as violações de teste:"
echo "  1. SSH-001/002: PermitRootLogin yes e permissão 0644 em /etc/ssh/sshd_config"
echo "  2. SUDO-001/002: NOPASSWD indevido para %wheel e estagiario em /etc/sudoers.d/99-inseguro-ati"
echo "  3. ACC-001: Usuário 'toor_demo' com UID 0 duplicado em /etc/passwd"
echo "  4. SUDO-003: Usuário 'ex_funcionario' adicionado como membro extra do grupo wheel"
echo "  5. OFF-001..005: 'ex_funcionario' com chave SSH ativa (chave privada em /root/ex_funcionario_demo_key)"
echo "  6. PERM-003: Permissão frouxa 0644 em /etc/shadow"
echo "  7. PERM-001: Executável com bit SUID (/usr/local/bin/suid_teste 4755)"
echo "  8. PAM-001/001b: deny=0 e unlock_time=0 em /etc/security/faillock.conf"
echo "  9. PAM-002: minlen=6 em /etc/security/pwquality.conf"
echo " 10. ACC-002: UMASK 022 frouxo em /etc/login.defs"
echo " 11. SELINUX=permissive em /etc/selinux/config (se presente)"
echo " 12. /var/www/uploads com permissão 0777 e shell executável"
echo " 13. Proteções de kernel sysctl desativadas (ip_forward, accept_redirects, va_space)"
echo "=============================================================================="
echo "Execute agora na VM:"
echo "  python3 -m hardener audit"
echo "  python3 -m hardener enforce"
echo "  sudo python3 -m hardener enforce --apply"
echo "Para testar o acesso SSH de ex_funcionario antes e depois do offboarding:"
echo "  ssh -i /root/ex_funcionario_demo_key ex_funcionario@localhost"
