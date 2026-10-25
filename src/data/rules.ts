import { Regra } from '../types';

export const REGRAS_PADRAO: Regra[] = [
  // Trilha B: identidade e privilégio (dores 5 e 6)
  {
    id: "SSH-001",
    descricao: "Desabilitar login direto como root no SSH",
    referencia: "CIS RHEL 9 - 5.2.8 SSH PermitRootLogin",
    dor_ati: [6],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "sshd_config",
    parametros: {
      chave: "PermitRootLogin",
      valor: "no"
    },
    recarregar: "sshd",
    origem: "rules/ssh.yaml"
  },
  {
    id: "SSH-002",
    descricao: "Permissões restritivas no arquivo /etc/ssh/sshd_config (0600 root:root)",
    referencia: "CIS RHEL 9 - 5.2.1 sshd_config permissions",
    dor_ati: [6],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "permissao_arquivo",
    parametros: {
      caminho: "/etc/ssh/sshd_config",
      modo: "0600",
      dono: "root",
      grupo: "root"
    },
    recarregar: "sshd",
    origem: "rules/ssh.yaml"
  },
  {
    id: "SUDO-001",
    descricao: "Impedir diretiva NOPASSWD indevida no sudoers e sudoers.d",
    referencia: "CIS RHEL 9 - 5.3.4 Ensure sudo commands require authentication",
    dor_ati: [6],
    severidade: "critica",
    plataforma: "rhel9",
    primitiva: "sudoers",
    parametros: {
      proibir: "NOPASSWD"
    },
    recarregar: "sudoers",
    origem: "rules/accounts.yaml"
  },
  {
    id: "SUDO-002",
    descricao: "Impedir permissões excessivas ALL indevidas em sudoers",
    referencia: "CIS RHEL 9 - 5.3.3 Sudoers restricted specification",
    dor_ati: [6],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "sudoers",
    parametros: {
      verificar_regras_gerais: true
    },
    recarregar: "sudoers",
    origem: "rules/accounts.yaml"
  },
  {
    id: "SUDO-003",
    descricao: "Grupo wheel restrito exclusivamente a administradores autorizados",
    referencia: "CIS RHEL 9 - 5.3.2 Restrict wheel group membership",
    dor_ati: [6],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "conta_usuario",
    parametros: {
      grupo: "wheel",
      autorizados: ["root", "admin_ati", "secops"]
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "ACC-001",
    descricao: "UID 0 exclusivo para conta root",
    referencia: "CIS RHEL 9 - 5.4.3 Ensure root is the only UID 0 account",
    dor_ati: [6],
    severidade: "critica",
    plataforma: "rhel9",
    primitiva: "conta_usuario",
    parametros: {
      uid_zero_apenas: "root"
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "ACC-002",
    descricao: "Configurar umask padrão seguro (027)",
    referencia: "CIS RHEL 9 - 5.4.4 Ensure default user umask is 027 or more restrictive",
    dor_ati: [6],
    severidade: "media",
    plataforma: "rhel9",
    primitiva: "permissao_arquivo",
    parametros: {
      caminho: "/etc/profile.d/umask.sh",
      modo: "0644",
      conteudo: "umask 027\n"
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "PERM-001",
    descricao: "Auditoria e restrição de binários com SUID/SGID",
    referencia: "CIS RHEL 9 - 6.1.13 Ensure no unauthorized SUID/SGID files exist",
    dor_ati: [6],
    severidade: "media",
    plataforma: "rhel9",
    primitiva: "suid_sgid",
    parametros: {
      bloquear_inseguros: ["rlogin", "rsh", "rcp"]
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "PERM-002",
    descricao: "Permissões restritivas de /etc/shadow (0000) e /etc/passwd (0644)",
    referencia: "CIS RHEL 9 - 6.1.2 Ensure permissions on /etc/shadow and /etc/passwd",
    dor_ati: [6],
    severidade: "critica",
    plataforma: "rhel9",
    primitiva: "permissao_arquivo",
    parametros: {
      caminho: "/etc/shadow",
      modo: "0000",
      dono: "root",
      grupo: "root"
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "PAM-001",
    descricao: "Configurar pam_faillock contra ataques de força bruta (deny=5, unlock_time=900)",
    referencia: "CIS RHEL 9 - 5.3.1 Ensure password failed attempts lockout is configured",
    dor_ati: [6],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "pam_faillock",
    parametros: {
      deny: 5,
      unlock_time: 900
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "PAM-002",
    descricao: "Configurar pam_pwquality para complexidade mínima de senha (minlen=14)",
    referencia: "CIS RHEL 9 - 5.3.2 Ensure password quality requirements are enforced",
    dor_ati: [6],
    severidade: "media",
    plataforma: "rhel9",
    primitiva: "pam_pwquality",
    parametros: {
      minlen: 14,
      dcredit: -1,
      ucredit: -1
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "OFF-001",
    descricao: "Contas locais inativas ou fora da lista de autorizados bloqueadas (usermod -L, chage -E 0)",
    referencia: "Requisito ATI - Trilha B Offboarding (Políticas de desligamento)",
    dor_ati: [5],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "offboarding",
    parametros: {
      acao: "bloquear_inativos",
      expiracao_dias: 90
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "OFF-002",
    descricao: "Definir shell nologin (/sbin/nologin) nas contas desativadas",
    referencia: "Requisito ATI - Trilha B Offboarding Shell",
    dor_ati: [5],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "offboarding",
    parametros: {
      shell: "/sbin/nologin"
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "OFF-003",
    descricao: "Arquivar e revogar authorized_keys de credenciais desligadas",
    referencia: "Requisito ATI - Trilha B Revogação de Chaves SSH",
    dor_ati: [5],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "offboarding",
    parametros: {
      revogar_ssh_keys: true
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "OFF-004",
    descricao: "Remover contas bloqueadas ou sem atividade recente do grupo administrativo wheel",
    referencia: "Requisito ATI - Trilha B Revogação de Privilégio Administrativo",
    dor_ati: [5, 6],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "offboarding",
    parametros: {
      limpar_wheel: true
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "OFF-005",
    descricao: "Encerrar sessões ativas (kill) de contas locais desligadas",
    referencia: "Requisito ATI - Trilha B Encerramento de Sessões Ativas",
    dor_ati: [5],
    severidade: "media",
    plataforma: "rhel9",
    primitiva: "offboarding",
    parametros: {
      encerrar_sessoes: true
    },
    origem: "rules/accounts.yaml"
  },
  {
    id: "OFF-006",
    descricao: "Relatório de auditoria de contas inativas (>90 dias sem autenticação)",
    referencia: "CIS RHEL 9 - 5.4.1 Ensure inactive password lock is 30 days or less",
    dor_ati: [5],
    severidade: "media",
    plataforma: "rhel9",
    primitiva: "offboarding",
    parametros: {
      auditoria_inatividade: true
    },
    origem: "rules/accounts.yaml"
  },

  // Trilha C: host, rede e dados (dores 1, 2 e 3)
  {
    id: "NET-001",
    descricao: "Firewalld ativo com zona restritiva e apenas serviços declarados",
    referencia: "CIS RHEL 9 - 3.4.2 Ensure firewalld service is enabled and active",
    dor_ati: [3],
    severidade: "critica",
    plataforma: "rhel9",
    primitiva: "firewalld",
    parametros: {
      servico_ativo: true,
      zona_padrao: "drop",
      servicos_permitidos: ["ssh"]
    },
    recarregar: "firewalld",
    origem: "rules/network.yaml"
  },
  {
    id: "NET-002",
    descricao: "Portas em escuta restritas estritamente à matriz autorizada",
    referencia: "CIS RHEL 9 - 3.5 Network ports audit",
    dor_ati: [3],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "portas_escuta",
    parametros: {
      portas_permitidas: [22]
    },
    origem: "rules/network.yaml"
  },
  {
    id: "NET-003",
    descricao: "Configurar AllowGroups no SSH para limitar conexões remotas",
    referencia: "CIS RHEL 9 - 5.2.16 Ensure SSH access is limited (AllowGroups)",
    dor_ati: [3, 6],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "sshd_config",
    parametros: {
      chave: "AllowGroups",
      valor: "sshusers wheel"
    },
    recarregar: "sshd",
    origem: "rules/ssh.yaml"
  },
  {
    id: "NET-004",
    descricao: "Desabilitar encaminhamento de pacotes IPv4 (net.ipv4.ip_forward = 0)",
    referencia: "CIS RHEL 9 - 3.1.1 Ensure IP forwarding is disabled",
    dor_ati: [3],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "sysctl",
    parametros: {
      parametro: "net.ipv4.ip_forward",
      valor: "0"
    },
    origem: "rules/network.yaml"
  },
  {
    id: "NET-005",
    descricao: "Desabilitar redirects ICMP (accept_redirects e send_redirects = 0)",
    referencia: "CIS RHEL 9 - 3.2.1 Ensure packet redirect sending and accepting is disabled",
    dor_ati: [3],
    severidade: "media",
    plataforma: "rhel9",
    primitiva: "sysctl",
    parametros: {
      parametro: "net.ipv4.conf.all.accept_redirects",
      valor: "0"
    },
    origem: "rules/network.yaml"
  },
  {
    id: "NET-006",
    descricao: "Habilitar filtro de rota reversa (rp_filter) e log de pacotes martian",
    referencia: "CIS RHEL 9 - 3.2.7 Ensure Reverse Path Filtering is enabled",
    dor_ati: [3],
    severidade: "media",
    plataforma: "rhel9",
    primitiva: "sysctl",
    parametros: {
      parametro: "net.ipv4.conf.all.rp_filter",
      valor: "1"
    },
    origem: "rules/network.yaml"
  },
  {
    id: "MNT-001",
    descricao: "Partição /tmp montada com opções noexec, nosuid e nodev",
    referencia: "CIS RHEL 9 - 1.1.2 Ensure /tmp has noexec, nosuid, nodev options",
    dor_ati: [1],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "montagem",
    parametros: {
      ponto: "/tmp",
      opcoes: ["noexec", "nosuid", "nodev"]
    },
    origem: "rules/mounts.yaml"
  },
  {
    id: "MNT-002",
    descricao: "Partição /var/tmp montada com opções noexec, nosuid e nodev",
    referencia: "CIS RHEL 9 - 1.1.4 Ensure /var/tmp has noexec, nosuid, nodev options",
    dor_ati: [1],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "montagem",
    parametros: {
      ponto: "/var/tmp",
      opcoes: ["noexec", "nosuid", "nodev"]
    },
    origem: "rules/mounts.yaml"
  },
  {
    id: "MNT-003",
    descricao: "Memória compartilhada /dev/shm montada com noexec, nosuid e nodev",
    referencia: "CIS RHEL 9 - 1.1.6 Ensure /dev/shm has noexec, nosuid, nodev options",
    dor_ati: [1],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "montagem",
    parametros: {
      ponto: "/dev/shm",
      opcoes: ["noexec", "nosuid", "nodev"]
    },
    origem: "rules/mounts.yaml"
  },
  {
    id: "SYS-001",
    descricao: "SELinux ativado no modo enforcing (/etc/selinux/config)",
    referencia: "CIS RHEL 9 - 1.6.1.2 Ensure the SELinux state is enforcing",
    dor_ati: [1],
    severidade: "critica",
    plataforma: "rhel9",
    primitiva: "selinux",
    parametros: {
      modo: "enforcing"
    },
    origem: "rules/system.yaml"
  },
  {
    id: "SYS-002",
    descricao: "Auditoria e remoção de arquivos world-writable sem sticky bit e sem dono",
    referencia: "CIS RHEL 9 - 6.1.10 Ensure no world writable files exist without sticky bit",
    dor_ati: [1],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "permissao_arquivo",
    parametros: {
      verificar_sticky_bit: true
    },
    origem: "rules/system.yaml"
  },
  {
    id: "SVC-001",
    descricao: "Serviços inseguros legados desativados (telnet, rsh, tftp, vsftpd)",
    referencia: "CIS RHEL 9 - 2.1 Ensure legacy insecure services are not installed or disabled",
    dor_ati: [1],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "servico",
    parametros: {
      desativar: ["telnet.socket", "rsh.socket", "tftp.socket", "vsftpd"]
    },
    origem: "rules/system.yaml"
  },
  {
    id: "KRN-001",
    descricao: "Proteções do Kernel (randomize_va_space=2, kptr_restrict=2, dmesg_restrict=1)",
    referencia: "CIS RHEL 9 - 1.5.1 Ensure address space layout randomization (ASLR) is enabled",
    dor_ati: [1],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "sysctl",
    parametros: {
      parametro: "kernel.randomize_va_space",
      valor: "2"
    },
    origem: "rules/system.yaml"
  },
  {
    id: "UPL-001",
    descricao: "Diretórios de upload declarados sem bit de execução (noexec)",
    referencia: "Requisito ATI - Trilha C Prevenção de Uploads Executáveis",
    dor_ati: [2],
    severidade: "critica",
    plataforma: "rhel9",
    primitiva: "permissao_arquivo",
    parametros: {
      caminho: "/var/www/uploads",
      modo: "0750",
      remover_exec: true
    },
    origem: "rules/uploads.yaml"
  },
  {
    id: "UPL-002",
    descricao: "Dono e grupo restritos nos diretórios de upload (root:apache / 0750)",
    referencia: "Requisito ATI - Trilha C Permissão de Uploads",
    dor_ati: [2],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "permissao_arquivo",
    parametros: {
      caminho: "/var/www/uploads",
      dono: "root",
      grupo: "apache"
    },
    origem: "rules/uploads.yaml"
  },
  {
    id: "UPL-003",
    descricao: "Montagem isolada com noexec, nosuid, nodev para storage de uploads",
    referencia: "Requisito ATI - Trilha C Montagem de Uploads",
    dor_ati: [2],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "montagem",
    parametros: {
      ponto: "/var/www/uploads",
      opcoes: ["noexec", "nosuid", "nodev"]
    },
    origem: "rules/uploads.yaml"
  },
  {
    id: "UPL-004",
    descricao: "Contexto SELinux sem permissão de execução de scripts em uploads",
    referencia: "Requisito ATI - Trilha C SELinux httpd_sys_rw_content_t",
    dor_ati: [2],
    severidade: "alta",
    plataforma: "rhel9",
    primitiva: "selinux",
    parametros: {
      caminho: "/var/www/uploads",
      tipo: "httpd_sys_rw_content_t"
    },
    origem: "rules/uploads.yaml"
  }
];

export const INITIAL_FILES: Record<string, string> = {
  "/etc/os-release": `NAME="Red Hat Enterprise Linux"
VERSION="9.4 (Plow)"
ID="rhel"
ID_LIKE="fedora"
VERSION_ID="9.4"
PLATFORM_ID="platform:el9"
PRETTY_NAME="Red Hat Enterprise Linux 9.4 (Plow)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"
HOME_URL="https://www.redhat.com/"
DOCUMENTATION_URL="https://access.redhat.com/documentation/red_hat_enterprise_linux/9/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"`,

  "/etc/hardener-vm": "# Marcador de segurança que autoriza a execução do enforce --apply nesta máquina virtual de testes.",

  "/etc/ssh/sshd_config": `# OpenSSH SSHD Configuration
Include /etc/ssh/sshd_config.d/*.conf
Port 22
AddressFamily any
ListenAddress 0.0.0.0
# Padrões inseguros pré-hardening:
PermitRootLogin yes
PasswordAuthentication yes
X11Forwarding yes
MaxAuthTries 6`,

  "/etc/sudoers": `# sudoers file
Defaults   !visiblepw
Defaults    always_set_home
Defaults    match_group_by_gid
Defaults    env_reset
Defaults    env_keep =  "COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS"

root    ALL=(ALL)       ALL
%wheel  ALL=(ALL)       NOPASSWD: ALL
estagiario ALL=(ALL)   NOPASSWD: ALL`,

  "/etc/shadow": `root:$6$salt$hashedpassword:19800:0:99999:7:::
admin_ati:$6$salt$hashedpassword:19800:0:99999:7:::
estagiario:$6$salt$hashedpassword:19500:0:99999:7:::
ex_funcionario:$6$salt$oldhash:19200:0:99999:7:::
servico_legado:$6$salt$oldhash:19100:0:99999:7:::`,

  "/etc/passwd": `root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
admin_ati:x:1000:1000:Admin ATI:/home/admin_ati:/bin/bash
estagiario:x:1001:1001:Estagiario Temp:/home/estagiario:/bin/bash
ex_funcionario:x:1002:1002:Ex Funcionario:/home/ex_funcionario:/bin/bash
servico_legado:x:1003:1003:Servico Descontinuado:/home/servico_legado:/bin/bash`,

  "/etc/fstab": `# /etc/fstab: static file system information.
UUID=1234-abcd-5678 / ext4 defaults 1 1
UUID=abcd-5678-ef01 /tmp ext4 defaults 0 0
UUID=ef01-2345-6789 /var/tmp ext4 defaults 0 0
tmpfs /dev/shm tmpfs defaults 0 0`,

  "/etc/selinux/config": `# SELINUX= can take one of these three values:
#     enforcing - SELinux security policy is enforced.
#     permissive - SELinux prints warnings instead of enforcing.
#     disabled - No SELinux policy is loaded.
SELINUX=permissive
SELINUXTYPE=targeted`,

  "/etc/sysctl.d/99-sysctl.conf": `# Kernel sysctl settings
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.all.rp_filter = 0
kernel.randomize_va_space = 0`,
};
