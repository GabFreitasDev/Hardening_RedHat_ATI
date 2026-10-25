#!/bin/bash
# ==============================================================================
# Script de Demonstração: sujar_servidor.sh
# Cria deliberadamente as violações no RHEL 9 para testar audit, enforce e rollback.
# Requisito do Escopo ATI - Seção 12
# ==============================================================================

set -euo pipefail

echo "[+] Configurando violações de segurança para teste do Hardener ATI..."

# 1. Dor 6 / Dor 3: PermitRootLogin no SSH
if [ -f /etc/ssh/sshd_config ]; then
  sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || true
  chmod 0644 /etc/ssh/sshd_config || true
fi

# 2. Dor 6: Sudoers com NOPASSWD indevido
mkdir -p /etc/sudoers.d
echo "%wheel ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-inseguro-ati
echo "estagiario ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/99-inseguro-ati
chmod 0440 /etc/sudoers.d/99-inseguro-ati

# 3. Dor 5: Criar usuário desativado fora da lista de autorizados com chave SSH ativa
if ! id "ex_funcionario" &>/dev/null; then
  useradd -m -s /bin/bash ex_funcionario || true
  mkdir -p /home/ex_funcionario/.ssh
  echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhostKeyExFuncionario chave_orfa@ati" > /home/ex_funcionario/.ssh/authorized_keys
  chmod 700 /home/ex_funcionario/.ssh
  chmod 600 /home/ex_funcionario/.ssh/authorized_keys
  chown -R ex_funcionario:ex_funcionario /home/ex_funcionario/.ssh
fi

# 4. Dor 1: SELinux em modo Permissive (se selinux estiver ativo)
if command -v setenforce &>/dev/null; then
  setenforce 0 || true
fi
if [ -f /etc/selinux/config ]; then
  sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config || true
fi

# 5. Dor 2: Diretório de uploads inseguro com permissão de execução
mkdir -p /var/www/uploads
chmod 0777 /var/www/uploads
echo '#!/bin/bash\necho "Executavel malicioso"' > /var/www/uploads/shell.sh
chmod +x /var/www/uploads/shell.sh

# 6. Dor 3: Desativar proteções de rede do kernel no sysctl
sysctl -w net.ipv4.ip_forward=1 2>/dev/null || true
sysctl -w net.ipv4.conf.all.accept_redirects=1 2>/dev/null || true
sysctl -w kernel.randomize_va_space=0 2>/dev/null || true

# 7. Criar marcador de segurança se for VM de testes
touch /etc/hardener-vm

echo "[OK] Servidor RHEL 9 preparado com as violações de teste."
echo "Execute agora: python3 -m hardener audit"
