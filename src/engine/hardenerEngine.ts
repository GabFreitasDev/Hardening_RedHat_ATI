import {
  BackupSession,
  DorAtiId,
  NOMES_DORES,
  ORDEM_STATUS,
  Regra,
  RelatorioJSON,
  Resultado,
  StatusRegra,
  Verificacao,
  VirtualSystemState
} from '../types';

export const HARDENER_VERSION = "0.1.0";

export class HardenerEngine {
  public system: VirtualSystemState;
  public backups: BackupSession[];
  public executionLog: string[];

  constructor(initialSystem: VirtualSystemState, initialBackups: BackupSession[] = []) {
    this.system = JSON.parse(JSON.stringify(initialSystem));
    this.backups = JSON.parse(JSON.stringify(initialBackups));
    this.executionLog = [];
  }

  // --- TRAVA VM CHECK ---
  public travaVm(): string | null {
    if (this.system.plataforma !== "rhel9") {
      return `plataforma '${this.system.plataforma}': enforce --apply só roda em RHEL 9 (ou Rocky/Alma 9)`;
    }
    if (!this.system.isRoot) {
      return "enforce --apply exige root (use sudo)";
    }
    if (!this.system.hasVmMarker && !this.system.files["/etc/hardener-vm"]) {
      return "trava de segurança: /etc/hardener-vm não existe. O enforce só deve rodar na VM de testes; nela, crie o marcador com: sudo touch /etc/hardener-vm";
    }
    return null;
  }

  // --- RULE VERIFICATION ---
  public verificarRegra(regra: Regra): { resultado: Resultado; descricaoMudanca: string } {
    if (this.system.plataforma !== "desconhecida" && regra.plataforma !== this.system.plataforma) {
      return {
        resultado: {
          regra,
          status: "PULADO",
          detalhe: `regra é de ${regra.plataforma}; sistema é ${this.system.plataforma}`,
          mudancas: []
        },
        descricaoMudanca: ""
      };
    }

    let verif: Verificacao;
    let descricaoMudanca = "";

    switch (regra.primitiva) {
      case "sshd_config": {
        const chave = String(regra.parametros.chave || "").toLowerCase();
        const esperado = String(regra.parametros.valor || "").trim();
        descricaoMudanca = `gravar '${regra.parametros.chave} ${esperado}' em /etc/ssh/sshd_config.d/00-hardener.conf`;

        // Check drop-in 00-hardener.conf first (first-match wins in sshd)
        let valorAtual: string | null = null;
        const dropin = this.system.files["/etc/ssh/sshd_config.d/00-hardener.conf"];
        if (dropin) {
          for (const line of dropin.split("\n")) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith("#")) {
              const parts = trimmed.split(/\s+/, 2);
              if (parts[0].toLowerCase() === chave) {
                valorAtual = parts[1];
                break;
              }
            }
          }
        }

        // If not in drop-in, check main sshd_config
        if (valorAtual === null) {
          const mainConf = this.system.files["/etc/ssh/sshd_config"] || "";
          for (const line of mainConf.split("\n")) {
            const trimmed = line.trim();
            if (trimmed && !trimmed.startsWith("#")) {
              const parts = trimmed.split(/\s+/, 2);
              if (parts[0].toLowerCase() === chave) {
                valorAtual = parts[1];
                break;
              }
            }
          }
        }

        const conforme = valorAtual !== null && valorAtual.toLowerCase() === esperado.toLowerCase();
        verif = {
          conforme,
          atual: valorAtual || "não definido (padrão OpenSSH)",
          esperado,
          detalhe: conforme ? "" : `diretiva ${regra.parametros.chave} difere do padrão de segurança`
        };
        break;
      }

      case "permissao_arquivo": {
        const caminho = regra.parametros.caminho || "";
        const modoEsperado = regra.parametros.modo;
        const donoEsperado = regra.parametros.dono || "root";
        const grupoEsperado = regra.parametros.grupo || "root";

        descricaoMudanca = `ajustar permissões de ${caminho} para modo ${modoEsperado || 'restrito'} (${donoEsperado}:${grupoEsperado})`;

        if (caminho === "/etc/ssh/sshd_config") {
          const dropin = this.system.files["/etc/ssh/sshd_config.d/00-hardener.conf"];
          const conf = this.system.files["/etc/ssh/sshd_config.perms"] || (dropin ? "0600 root:root" : "0644 root:root");
          const conforme = conf === "0600 root:root";
          verif = {
            conforme,
            atual: conf,
            esperado: "0600 root:root",
            detalhe: conforme ? "" : "permissões excessivas no arquivo principal de configuração SSH"
          };
        } else if (caminho === "/etc/shadow") {
          const perm = this.system.files["/etc/shadow.perms"] || "0640 root:root";
          const conforme = perm === "0000 root:root" || perm === "0400 root:root";
          verif = {
            conforme,
            atual: perm,
            esperado: "0000 root:root",
            detalhe: conforme ? "" : "arquivo sensível de senhas /etc/shadow com leitura não autorizada"
          };
        } else if (caminho === "/var/www/uploads") {
          const perm = this.system.files["/var/www/uploads.perms"] || "0777 root:root";
          const conforme = perm === "0750 root:apache";
          verif = {
            conforme,
            atual: perm,
            esperado: "0750 root:apache (sem bit +x)",
            detalhe: conforme ? "" : "diretório de uploads exposto a execução direta de arquivos"
          };
        } else if (regra.parametros.verificar_sticky_bit) {
          const worldWritableCount = this.system.files["/var/tmp/insecure_files_count"] !== undefined
            ? parseInt(this.system.files["/var/tmp/insecure_files_count"], 10)
            : 3;
          verif = {
            conforme: worldWritableCount === 0,
            atual: `${worldWritableCount} arquivo(s) world-writable sem sticky bit`,
            esperado: "0 arquivos world-writable desprotegidos",
            detalhe: worldWritableCount === 0 ? "" : "encontrados arquivos world-writable suscetíveis a sobrescrita"
          };
          descricaoMudanca = "remover permissão de escrita global ou adicionar sticky bit (+t)";
        } else {
          const existe = this.system.files[caminho] !== undefined;
          verif = {
            conforme: existe,
            atual: existe ? "configurado" : "ausente",
            esperado: "configurado",
            detalhe: existe ? "" : `${caminho} não encontrado`
          };
        }
        break;
      }

      case "sudoers": {
        const sudoers = this.system.files["/etc/sudoers"] || "";
        const temNoPasswd = /NOPASSWD/i.test(sudoers);
        descricaoMudanca = "remover diretiva NOPASSWD de /etc/sudoers e /etc/sudoers.d/*";

        if (regra.parametros.proibir === "NOPASSWD") {
          verif = {
            conforme: !temNoPasswd,
            atual: temNoPasswd ? "NOPASSWD presente em %wheel e estagiario" : "todos os comandos exigem autenticação",
            esperado: "sem NOPASSWD (autenticação obrigatória)",
            detalhe: temNoPasswd ? "diretiva NOPASSWD permite elevação de privilégio sem senha" : ""
          };
        } else {
          const temExcessos = sudoers.includes("estagiario ALL=(ALL)   NOPASSWD: ALL");
          verif = {
            conforme: !temExcessos,
            atual: temExcessos ? "privilégios ALL irrestritos concedidos a contas não homologadas" : "sudoers em conformidade",
            esperado: "regras restritas à lista de operadores certificados",
            detalhe: temExcessos ? "conta não autorizada possui privilégio total ALL" : ""
          };
          descricaoMudanca = "remover declaração irrestrita de contas não homologadas no sudoers";
        }
        break;
      }

      case "conta_usuario": {
        const passwd = this.system.files["/etc/passwd"] || "";
        descricaoMudanca = "sanitizar contas locais e grupo administrativo";

        if (regra.parametros.uid_zero_apenas) {
          const linhasUidZero = passwd.split("\n").filter(l => {
            const parts = l.split(":");
            return parts.length > 2 && parts[2] === "0";
          });
          const conforme = linhasUidZero.length === 1 && linhasUidZero[0].startsWith("root:");
          verif = {
            conforme,
            atual: `UID 0 atribuído a: ${linhasUidZero.map(l => l.split(":")[0]).join(", ")}`,
            esperado: "UID 0 exclusivo para 'root'",
            detalhe: conforme ? "" : "contas adicionais com UID 0 violam o princípio de privilégio mínimo"
          };
        } else if (regra.parametros.grupo === "wheel") {
          const membrosAtuais = (this.system.files["/etc/group.wheel"] || "root,admin_ati,estagiario").split(",");
          const autorizados: string[] = regra.parametros.autorizados || ["root", "admin_ati", "secops"];
          const indevidos = membrosAtuais.filter(m => !autorizados.includes(m));
          const conforme = indevidos.length === 0;
          verif = {
            conforme,
            atual: `membros de wheel: [${membrosAtuais.join(", ")}]`,
            esperado: `apenas autorizados: [${autorizados.join(", ")}]`,
            detalhe: conforme ? "" : `contas não autorizadas no grupo wheel: ${indevidos.join(", ")}`
          };
          descricaoMudanca = `remover contas [${indevidos.join(", ")}] do grupo wheel`;
        } else {
          verif = { conforme: true, atual: "ok", esperado: "ok", detalhe: "" };
        }
        break;
      }

      case "offboarding": {
        const passwd = this.system.files["/etc/passwd"] || "";
        const contasBloqueadas = this.system.files["/var/lib/hardener/locked_accounts"] || "";
        const temInativos = passwd.includes("ex_funcionario") || passwd.includes("servico_legado");

        if (regra.parametros.acao === "bloquear_inativos") {
          const conforme = contasBloqueadas.includes("ex_funcionario") && contasBloqueadas.includes("servico_legado");
          verif = {
            conforme,
            atual: conforme ? "contas inativas bloqueadas (usermod -L)" : "contas de colaboradores desligados ativas no /etc/shadow",
            esperado: "contas desligadas bloqueadas com chage -E 0 e usermod -L",
            detalhe: conforme ? "" : "2 contas inativas identificadas sem bloqueio formal"
          };
          descricaoMudanca = "executar usermod -L e chage -E 0 nas contas [ex_funcionario, servico_legado]";
        } else if (regra.parametros.shell) {
          const hasBash = passwd.split("\n").some(l => (l.includes("ex_funcionario") || l.includes("servico_legado")) && l.endsWith("/bin/bash"));
          verif = {
            conforme: !hasBash,
            atual: hasBash ? "shell /bin/bash associado a contas desligadas" : "shell /sbin/nologin aplicado",
            esperado: "/sbin/nologin em contas desativadas",
            detalhe: hasBash ? "shell interativo disponível para identidades revogadas" : ""
          };
          descricaoMudanca = "alterar shell para /sbin/nologin nas contas desativadas";
        } else if (regra.parametros.revogar_ssh_keys) {
          const keysRevogadas = this.system.files["/var/lib/hardener/revoked_keys"] === "true";
          verif = {
            conforme: keysRevogadas,
            atual: keysRevogadas ? "chaves SSH arquivadas e removidas dos diretórios home" : "chaves autorizadas encontradas em contas desligadas",
            esperado: "authorized_keys arquivado e removido",
            detalhe: keysRevogadas ? "" : "arquivos authorized_keys ativos em ~/.ssh de contas desligadas"
          };
          descricaoMudanca = "mover ~/.ssh/authorized_keys para /var/backups/revoked_keys/";
        } else if (regra.parametros.limpar_wheel) {
          const wheelMembers = this.system.files["/etc/group.wheel"] || "root,admin_ati,estagiario";
          const conforme = !wheelMembers.includes("estagiario") && !wheelMembers.includes("ex_funcionario");
          verif = {
            conforme,
            atual: wheelMembers.includes("estagiario") ? "estagiario permanece no grupo wheel" : "nenhuma conta inativa em wheel",
            esperado: "apenas administradores efetivos em wheel",
            detalhe: conforme ? "" : "conta inativa possui privilégios de superusuário"
          };
          descricaoMudanca = "remover estagiario do grupo wheel (gpasswd -d estagiario wheel)";
        } else {
          verif = {
            conforme: true,
            atual: "auditoria concluída",
            esperado: "auditoria concluída",
            detalhe: ""
          };
          descricaoMudanca = "gerar auditoria detalhada de inatividade";
        }
        break;
      }

      case "pam_faillock": {
        const pamConf = this.system.files["/etc/security/faillock.conf"] || "";
        const conforme = pamConf.includes("deny = 5") && pamConf.includes("unlock_time = 900");
        verif = {
          conforme,
          atual: conforme ? "deny = 5, unlock_time = 900" : (pamConf ? "configuração não restritiva" : "não configurado"),
          esperado: "deny = 5, unlock_time = 900",
          detalhe: conforme ? "" : "bloqueio de tentativas de força bruta (pam_faillock) inativo"
        };
        descricaoMudanca = "definir 'deny = 5' e 'unlock_time = 900' em /etc/security/faillock.conf";
        break;
      }

      case "pam_pwquality": {
        const pwConf = this.system.files["/etc/security/pwquality.conf"] || "";
        const conforme = pwConf.includes("minlen = 14") && pwConf.includes("dcredit = -1");
        verif = {
          conforme,
          atual: conforme ? "minlen = 14, dcredit = -1, ucredit = -1" : (pwConf ? "critérios brandos" : "padrão de fábrica sem reforço"),
          esperado: "minlen = 14, dcredit = -1, ucredit = -1",
          detalhe: conforme ? "" : "complexidade de senha fraca contra ataques de dicionário"
        };
        descricaoMudanca = "definir requisitos de complexidade em /etc/security/pwquality.conf";
        break;
      }

      case "sysctl": {
        const sysctlConf = this.system.files["/etc/sysctl.d/99-sysctl.conf"] || "";
        const param = String(regra.parametros.parametro || "");
        const valorEsperado = String(regra.parametros.valor || "");
        descricaoMudanca = `adicionar '${param} = ${valorEsperado}' em /etc/sysctl.d/99-sysctl.conf`;

        let valorAtual: string | null = null;
        for (const line of sysctlConf.split("\n")) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith("#") && trimmed.includes("=")) {
            const [k, v] = trimmed.split("=").map(s => s.trim());
            if (k === param) {
              valorAtual = v;
            }
          }
        }

        const conforme = valorAtual === valorEsperado;
        verif = {
          conforme,
          atual: valorAtual !== null ? `${param} = ${valorAtual}` : `${param} não definido (kernel default)`,
          esperado: `${param} = ${valorEsperado}`,
          detalhe: conforme ? "" : `parâmetro de segurança de rede do kernel não atende ao padrão CIS`
        };
        break;
      }

      case "montagem": {
        const ponto = regra.parametros.ponto || "";
        const fstab = this.system.files["/etc/fstab"] || "";
        descricaoMudanca = `adicionar opções 'noexec,nosuid,nodev' na montagem de ${ponto} no /etc/fstab`;

        let options: string[] = [];
        for (const line of fstab.split("\n")) {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 4 && parts[1] === ponto) {
            options = parts[3].split(",");
            break;
          }
        }

        const temNoexec = options.includes("noexec");
        const temNosuid = options.includes("nosuid");
        const temNodev = options.includes("nodev");
        const conforme = temNoexec && temNosuid && temNodev;

        verif = {
          conforme,
          atual: options.length > 0 ? options.join(",") : "ponto de montagem sem opções declaradas",
          esperado: "noexec,nosuid,nodev",
          detalhe: conforme ? "" : `partição ${ponto} permite execução de binários ou privilégios suid`
        };
        break;
      }

      case "selinux": {
        if (regra.parametros.modo) {
          const selinuxConf = this.system.files["/etc/selinux/config"] || "";
          const isEnforcing = /SELINUX=enforcing/i.test(selinuxConf);
          descricaoMudanca = "definir SELINUX=enforcing em /etc/selinux/config e acionar setenforce 1";
          verif = {
            conforme: isEnforcing,
            atual: isEnforcing ? "enforcing" : (/SELINUX=permissive/i.test(selinuxConf) ? "permissive" : "disabled"),
            esperado: "enforcing",
            detalhe: isEnforcing ? "" : "SELinux em modo não bloqueante compromete a contenção mandatória"
          };
        } else {
          const ctxUploads = this.system.files["/var/www/uploads.selinux"] || "httpd_sys_content_t";
          const conforme = ctxUploads === "httpd_sys_rw_content_t";
          descricaoMudanca = "ajustar contexto SELinux para httpd_sys_rw_content_t sem permissão de execução";
          verif = {
            conforme,
            atual: ctxUploads,
            esperado: "httpd_sys_rw_content_t (noexec context)",
            detalhe: conforme ? "" : "contexto SELinux permite execução de scripts sob diretório web"
          };
        }
        break;
      }

      case "firewalld": {
        const fwActive = this.system.services["firewalld"]?.active ?? false;
        const fwZone = this.system.files["/etc/firewalld/firewalld.conf.zone"] || "public";
        const conforme = fwActive && fwZone === "drop";
        descricaoMudanca = "ativar firewalld com zona restritiva 'drop' e liberar apenas porta SSH";
        verif = {
          conforme,
          atual: fwActive ? `ativo (zona: ${fwZone})` : "inativo",
          esperado: "ativo (zona padrão restritiva: drop)",
          detalhe: conforme ? "" : "firewall do host desativado ou utilizando zona permissiva"
        };
        break;
      }

      case "portas_escuta": {
        const portasPermitidas: number[] = regra.parametros.portas_permitidas || [22];
        const portasAtivas = (this.system.files["/var/run/listening_ports"] || "22,8080,23").split(",").map(Number);
        const indevidas = portasAtivas.filter(p => !portasPermitidas.includes(p));
        const conforme = indevidas.length === 0;
        descricaoMudanca = `encerrar serviços e fechar portas não autorizadas: [${indevidas.join(", ")}]`;
        verif = {
          conforme,
          atual: `portas abertas: [${portasAtivas.join(", ")}]`,
          esperado: `apenas autorizadas: [${portasPermitidas.join(", ")}]`,
          detalhe: conforme ? "" : `serviços escutando em portas inseguras: ${indevidas.join(", ")}`
        };
        break;
      }

      case "servico": {
        const desativar: string[] = regra.parametros.desativar || [];
        const servicosAtivos = (this.system.files["/var/run/active_legacy_services"] || "telnet.socket,tftp.socket").split(",").filter(Boolean);
        const presentes = servicosAtivos.filter(s => desativar.includes(s));
        const conforme = presentes.length === 0;
        descricaoMudanca = `desativar e mascarar serviços legados inseguros: [${presentes.join(", ")}]`;
        verif = {
          conforme,
          atual: presentes.length > 0 ? `ativos: [${presentes.join(", ")}]` : "nenhum serviço inseguro ativo",
          esperado: "todos os serviços inseguros desativados/desinstalados",
          detalhe: conforme ? "" : `serviços com vulnerabilidades conhecidas ativos no host: ${presentes.join(", ")}`
        };
        break;
      }

      default:
        verif = {
          conforme: false,
          atual: "desconhecido",
          esperado: "configurado",
          detalhe: `primitiva desconhecida: ${regra.primitiva}`
        };
    }

    const status: StatusRegra = verif.conforme ? "CONFORME" : "NAO_CONFORME";
    return {
      resultado: {
        regra,
        status,
        atual: verif.atual,
        esperado: verif.esperado,
        detalhe: verif.detalhe,
        mudancas: []
      },
      descricaoMudanca
    };
  }

  // --- AUDIT ---
  public auditar(regras: Regra[]): Resultado[] {
    this.log(`Executando auditoria em ${regras.length} regras...`);
    const resultados: Resultado[] = [];
    for (const regra of regras) {
      const { resultado } = this.verificarRegra(regra);
      resultados.push(resultado);
    }
    return resultados;
  }

  // --- ENFORCE DRY-RUN ---
  public aplicarDryRun(regras: Regra[]): Resultado[] {
    this.log(`Executando enforce em modo dry-run (simulação)...`);
    const resultados: Resultado[] = [];
    for (const regra of regras) {
      const { resultado, descricaoMudanca } = this.verificarRegra(regra);
      if (resultado.status === "NAO_CONFORME") {
        resultado.status = "SERIA_CORRIGIDO";
        resultado.detalhe = descricaoMudanca;
      }
      resultados.push(resultado);
    }
    return resultados;
  }

  // --- ENFORCE APPLY ---
  public aplicarApply(regras: Regra[]): { resultados: Resultado[]; erroTrava?: string; sessaoCriada?: BackupSession } {
    this.log(`Iniciando enforce --apply...`);
    const motivoTrava = this.travaVm();
    if (motivoTrava) {
      this.log(`RECUSADO: ${motivoTrava}`);
      return { resultados: [], erroTrava: motivoTrava };
    }

    const resultados: Resultado[] = [];
    const servicosPendentes: Record<string, Resultado[]> = {};
    let sessao: BackupSession | null = null;

    const agora = new Date();
    const sessionId = agora.toISOString().replace(/[-:]/g, "").slice(0, 15);

    for (const regra of regras) {
      const { resultado, descricaoMudanca } = this.verificarRegra(regra);
      resultados.push(resultado);

      if (resultado.status !== "NAO_CONFORME") {
        continue;
      }

      // We need to apply changes. Create backup session if not created yet
      if (!sessao) {
        sessao = {
          id: sessionId,
          criadoEm: agora.toISOString(),
          revertida: false,
          entradas: []
        };
      }

      // Record backups and apply modification to simulated files
      this.salvarEModificar(regra, sessao, resultado, descricaoMudanca);

      // Re-verify after modification
      const { resultado: v2 } = this.verificarRegra(regra);
      resultado.atual = v2.atual;

      if (v2.status === "CONFORME") {
        resultado.status = "CORRIGIDO";
        if (regra.recarregar) {
          if (!servicosPendentes[regra.recarregar]) {
            servicosPendentes[regra.recarregar] = [];
          }
          servicosPendentes[regra.recarregar].push(resultado);
        }
      } else {
        resultado.status = "FALHOU";
        resultado.detalhe = "continua não conforme após corrigir; alteração mantida (use rollback)";
      }
    }

    // Now validate and reload affected services (sshd, sudoers, firewalld, etc.)
    if (sessao && Object.keys(servicosPendentes).length > 0) {
      this.validarERecarregarServicos(servicosPendentes, sessao);
    }

    if (sessao && sessao.entradas.length > 0) {
      this.backups.unshift(sessao);
      this.log(`Sessão de backup ${sessao.id} gravada com ${sessao.entradas.length} arquivo(s).`);
    }

    return { resultados, sessaoCriada: sessao || undefined };
  }

  // --- SAVE BACKUP AND APPLY FIXES ---
  private salvarEModificar(regra: Regra, sessao: BackupSession, resultado: Resultado, descricaoMudanca: string) {
    const backupArquivo = (caminho: string, servico?: string) => {
      const existia = this.system.files[caminho] !== undefined;
      const original = existia ? this.system.files[caminho] : undefined;
      
      const jaSalvo = sessao.entradas.find(e => e.caminho === caminho);
      if (jaSalvo) {
        if (servico && !jaSalvo.servicos.includes(servico)) {
          jaSalvo.servicos.push(servico);
        }
        return;
      }

      sessao.entradas.push({
        caminho,
        existia,
        arquivo_backup: `arquivos/${String(sessao.entradas.length + 1).padStart(4, "0")}`,
        regra: regra.id,
        servicos: servico ? [servico] : [],
        conteudoOriginal: original
      });
    };

    switch (regra.primitiva) {
      case "sshd_config": {
        const dropinPath = "/etc/ssh/sshd_config.d/00-hardener.conf";
        backupArquivo(dropinPath, "sshd");

        const chave = String(regra.parametros.chave);
        const valor = String(regra.parametros.valor);
        const cabecalho = "# Gerenciado pela ferramenta hardener. Alterações manuais serão sobrescritas.\n";
        
        let conteudo = this.system.files[dropinPath] || cabecalho;
        const linhas = conteudo.split("\n").filter(l => {
          const parts = l.trim().split(/\s+/);
          return !(parts.length > 0 && parts[0].toLowerCase() === chave.toLowerCase());
        });
        linhas.push(`${chave} ${valor}`);
        this.system.files[dropinPath] = linhas.join("\n") + "\n";
        resultado.mudancas.push(`${dropinPath}: ${chave} ${valor}`);
        break;
      }

      case "permissao_arquivo": {
        const caminho = regra.parametros.caminho || "";
        if (caminho === "/etc/ssh/sshd_config") {
          backupArquivo(caminho, "sshd");
          this.system.files["/etc/ssh/sshd_config.perms"] = "0600 root:root";
          resultado.mudancas.push(`${caminho}: chmod 0600, chown root:root`);
        } else if (caminho === "/etc/shadow") {
          backupArquivo(caminho);
          this.system.files["/etc/shadow.perms"] = "0000 root:root";
          resultado.mudancas.push(`${caminho}: chmod 0000, chown root:root`);
        } else if (caminho === "/var/www/uploads") {
          backupArquivo(caminho);
          this.system.files["/var/www/uploads.perms"] = "0750 root:apache";
          resultado.mudancas.push(`${caminho}: chmod 0750, chown root:apache`);
        } else if (regra.parametros.verificar_sticky_bit) {
          this.system.files["/var/tmp/insecure_files_count"] = "0";
          resultado.mudancas.push("Removidas permissões world-writable e adicionado sticky bit em /tmp e /var/tmp");
        } else {
          backupArquivo(caminho);
          this.system.files[caminho] = regra.parametros.conteudo || "umask 027\n";
          resultado.mudancas.push(`Criado/ajustado ${caminho}`);
        }
        break;
      }

      case "sudoers": {
        backupArquivo("/etc/sudoers", "sudoers");
        let sudoers = this.system.files["/etc/sudoers"] || "";
        sudoers = sudoers.replace(/%wheel\s+ALL=\(ALL\)\s+NOPASSWD:\s+ALL/g, "%wheel ALL=(ALL) ALL");
        sudoers = sudoers.replace(/estagiario\s+ALL=\(ALL\)\s+NOPASSWD:\s+ALL/g, "# estagiario removido pelo hardener");
        this.system.files["/etc/sudoers"] = sudoers;
        resultado.mudancas.push("/etc/sudoers: revogado NOPASSWD e removido acesso irrestrito");
        break;
      }

      case "conta_usuario": {
        if (regra.parametros.grupo === "wheel") {
          backupArquivo("/etc/group.wheel");
          this.system.files["/etc/group.wheel"] = "root,admin_ati,secops";
          resultado.mudancas.push("/etc/group: removido 'estagiario' de wheel");
        }
        break;
      }

      case "offboarding": {
        backupArquivo("/etc/passwd");
        backupArquivo("/etc/shadow");
        let passwd = this.system.files["/etc/passwd"] || "";
        passwd = passwd.replace(/ex_funcionario:x:1002:1002:[^:]+:[^:]+:\/bin\/bash/, "ex_funcionario:x:1002:1002:Ex Funcionario:/home/ex_funcionario:/sbin/nologin");
        passwd = passwd.replace(/servico_legado:x:1003:1003:[^:]+:[^:]+:\/bin\/bash/, "servico_legado:x:1003:1003:Servico Descontinuado:/home/servico_legado:/sbin/nologin");
        this.system.files["/etc/passwd"] = passwd;
        this.system.files["/var/lib/hardener/locked_accounts"] = "ex_funcionario,servico_legado";
        this.system.files["/var/lib/hardener/revoked_keys"] = "true";
        resultado.mudancas.push("Bloqueadas contas [ex_funcionario, servico_legado], shell alterado para /sbin/nologin e chaves SSH arquivadas");
        break;
      }

      case "pam_faillock": {
        const path = "/etc/security/faillock.conf";
        backupArquivo(path);
        this.system.files[path] = `# Configurado pelo hardener ATI
deny = 5
unlock_time = 900
silent
`;
        resultado.mudancas.push(`${path}: deny=5, unlock_time=900`);
        break;
      }

      case "pam_pwquality": {
        const path = "/etc/security/pwquality.conf";
        backupArquivo(path);
        this.system.files[path] = `# Configurado pelo hardener ATI
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
`;
        resultado.mudancas.push(`${path}: minlen=14, dcredit=-1, ucredit=-1`);
        break;
      }

      case "sysctl": {
        const path = "/etc/sysctl.d/99-sysctl.conf";
        backupArquivo(path);
        const param = String(regra.parametros.parametro || "");
        const valor = String(regra.parametros.valor || "");
        let sysctl = this.system.files[path] || "";
        const lines = sysctl.split("\n").filter(l => !l.startsWith(param));
        lines.push(`${param} = ${valor}`);
        this.system.files[path] = lines.join("\n") + "\n";
        resultado.mudancas.push(`${path}: ${param} = ${valor}`);
        break;
      }

      case "montagem": {
        backupArquivo("/etc/fstab");
        const ponto = regra.parametros.ponto || "";
        let fstab = this.system.files["/etc/fstab"] || "";
        const lines = fstab.split("\n").map(l => {
          const parts = l.trim().split(/\s+/);
          if (parts.length >= 4 && parts[1] === ponto) {
            return `${parts[0]} ${parts[1]} ${parts[2]} defaults,noexec,nosuid,nodev ${parts[4] || "0"} ${parts[5] || "0"}`;
          }
          return l;
        });
        this.system.files["/etc/fstab"] = lines.join("\n");
        resultado.mudancas.push(`/etc/fstab: adicionadas opções noexec,nosuid,nodev em ${ponto}`);
        break;
      }

      case "selinux": {
        if (regra.parametros.modo) {
          backupArquivo("/etc/selinux/config");
          this.system.files["/etc/selinux/config"] = `SELINUX=enforcing\nSELINUXTYPE=targeted\n`;
          resultado.mudancas.push("/etc/selinux/config: SELINUX=enforcing");
        } else {
          this.system.files["/var/www/uploads.selinux"] = "httpd_sys_rw_content_t";
          resultado.mudancas.push("/var/www/uploads: semanage fcontext -a -t httpd_sys_rw_content_t");
        }
        break;
      }

      case "firewalld": {
        backupArquivo("/etc/firewalld/firewalld.conf.zone", "firewalld");
        this.system.files["/etc/firewalld/firewalld.conf.zone"] = "drop";
        if (this.system.services["firewalld"]) {
          this.system.services["firewalld"].active = true;
        }
        resultado.mudancas.push("firewalld: zona padrão drop configurada e serviço ativado");
        break;
      }

      case "portas_escuta": {
        this.system.files["/var/run/listening_ports"] = "22";
        resultado.mudancas.push("Fechadas portas 8080 e 23 (telnet)");
        break;
      }

      case "servico": {
        this.system.files["/var/run/active_legacy_services"] = "";
        resultado.mudancas.push("systemctl mask telnet.socket tftp.socket vsftpd");
        break;
      }
    }
  }

  // --- SERVICE VALIDATION & RELOAD ---
  private validarERecarregarServicos(servicosPendentes: Record<string, Resultado[]>, sessao: BackupSession) {
    for (const [servico, resultados] of Object.entries(servicosPendentes)) {
      let syntaxOk = true;
      let syntaxError = "";

      // Simulated service validation check (e.g. sshd -t, visudo -c)
      if (servico === "sshd" && this.system.simulatedSshdTFail) {
        syntaxOk = false;
        syntaxError = "sshd: /etc/ssh/sshd_config.d/00-hardener.conf: line 2: Directive syntax error simulado";
      }

      if (!syntaxOk) {
        this.log(`AVISO: Validação de '${servico}' falhou: ${syntaxError}. Revertendo arquivos...`);
        // Revert files for this service
        this.restaurarArquivosSessao(sessao, servico);
        for (const r of resultados) {
          r.status = "FALHOU";
          r.detalhe = `validação de '${servico}' falhou: ${syntaxError}; alterações revertidas`;
        }
        continue;
      }

      // Check simulated reload
      let reloadOk = true;
      let reloadError = "";
      if (this.system.simulatedReloadFail) {
        reloadOk = false;
        reloadError = `Job for ${servico}.service failed because the control process exited with error code.`;
      }

      if (!reloadOk) {
        this.log(`AVISO: Recarga de '${servico}' falhou: ${reloadError}. Revertendo arquivos...`);
        this.restaurarArquivosSessao(sessao, servico);
        for (const r of resultados) {
          r.status = "FALHOU";
          r.detalhe = `recarga de '${servico}' falhou: ${reloadError}; alterações revertidas`;
        }
      } else {
        this.log(`Serviço '${servico}' validado com sucesso e recarregado.`);
      }
    }
  }

  // --- ROLLBACK ---
  public reverter(sessaoId?: string): { acoes: string[]; sucesso: boolean; erro?: string } {
    let sessao: BackupSession | undefined;
    if (sessaoId) {
      sessao = this.backups.find(b => b.id === sessaoId);
    } else {
      sessao = this.backups.find(b => !b.revertida && b.entradas.length > 0);
    }

    if (!sessao) {
      const msg = "nenhuma sessão de backup pendente para reverter";
      this.log(`ERRO: ${msg}`);
      return { acoes: [], sucesso: false, erro: msg };
    }

    const acoes = [`sessão ${sessao.id}`];
    const acoesRestauracao = this.restaurarArquivosSessao(sessao);
    acoes.push(...acoesRestauracao);

    // Reload affected services
    const servicosAfetados = new Set<string>();
    sessao.entradas.forEach(e => e.servicos.forEach(s => servicosAfetados.add(s)));

    for (const servico of servicosAfetados) {
      acoes.push(`recarregado ${servico}`);
      this.log(`Serviço '${servico}' recarregado após rollback.`);
    }

    sessao.revertida = true;
    this.log(`Rollback da sessão ${sessao.id} concluído com sucesso.`);
    return { acoes, sucesso: true };
  }

  private restaurarArquivosSessao(sessao: BackupSession, filtroServico?: string): string[] {
    const acoes: string[] = [];
    const entradasReversas = [...sessao.entradas].reverse();

    for (const entry of entradasReversas) {
      if (filtroServico && !entry.servicos.includes(filtroServico)) {
        continue;
      }

      if (entry.existia && entry.conteudoOriginal !== undefined) {
        this.system.files[entry.caminho] = entry.conteudoOriginal;
        acoes.push(`restaurado ${entry.caminho}`);
      } else {
        delete this.system.files[entry.caminho];
        acoes.push(`removido ${entry.caminho} (não existia antes)`);
      }

      // Special file handlers (e.g. perms, selinux, accounts)
      if (entry.caminho === "/etc/ssh/sshd_config") {
        this.system.files["/etc/ssh/sshd_config.perms"] = "0644 root:root";
      } else if (entry.caminho === "/etc/shadow") {
        this.system.files["/etc/shadow.perms"] = "0640 root:root";
      } else if (entry.caminho === "/etc/passwd") {
        delete this.system.files["/var/lib/hardener/locked_accounts"];
        delete this.system.files["/var/lib/hardener/revoked_keys"];
      } else if (entry.caminho === "/etc/group.wheel") {
        this.system.files["/etc/group.wheel"] = "root,admin_ati,estagiario";
      } else if (entry.caminho === "/etc/firewalld/firewalld.conf.zone") {
        this.system.files["/etc/firewalld/firewalld.conf.zone"] = "public";
      }
    }

    return acoes;
  }

  // --- REPORT GENERATION (MATCHING hardener/report.py) ---
  public gerarRelatorio(resultados: Resultado[], modo: string, avisos: string[] = []): RelatorioJSON {
    const contagem: Record<string, number> = {};
    for (const s of ORDEM_STATUS) {
      contagem[s] = 0;
    }
    for (const r of resultados) {
      contagem[r.status] = (contagem[r.status] || 0) + 1;
    }
    const resumoFiltrado: Record<string, number> = {};
    for (const [k, v] of Object.entries(contagem)) {
      if (v > 0) resumoFiltrado[k] = v;
    }

    // Por dor
    const porDor: Record<string, { nome: string; total: number; conformes: number }> = {};
    for (const r of resultados) {
      if (r.status === "PULADO") continue;
      for (const d of r.regra.dor_ati) {
        const key = String(d);
        if (!porDor[key]) {
          porDor[key] = {
            nome: NOMES_DORES[d as DorAtiId] || `Dor ${d}`,
            total: 0,
            conformes: 0
          };
        }
        porDor[key].total += 1;
        if (r.status === "CONFORME" || r.status === "CORRIGIDO") {
          porDor[key].conformes += 1;
        }
      }
    }

    return {
      ferramenta: "hardener",
      versao: HARDENER_VERSION,
      modo,
      gerado_em: new Date().toISOString().replace(/\.\d{3}Z$/, ""),
      host: this.system.hostname,
      plataforma: this.system.plataforma,
      resumo: resumoFiltrado,
      por_dor: porDor,
      regras: resultados.map(r => ({
        id: r.regra.id,
        descricao: r.regra.descricao,
        referencia: r.regra.referencia,
        dor_ati: r.regra.dor_ati,
        severidade: r.regra.severidade,
        status: r.status,
        atual: r.atual,
        esperado: r.esperado,
        detalhe: r.detalhe,
        mudancas: r.mudancas
      })),
      avisos
    };
  }

  public relatorioTexto(dados: RelatorioJSON): string {
    const linhas: string[] = [
      `hardener ${dados.versao} | modo: ${dados.modo} | plataforma: ${dados.plataforma} | host: ${dados.host} | ${dados.gerado_em}`,
      ""
    ];

    for (const aviso of dados.avisos || []) {
      linhas.push(`NOTA: ${aviso}`);
    }
    if (dados.avisos && dados.avisos.length > 0) {
      linhas.push("");
    }

    for (const r of dados.regras) {
      const dores = r.dor_ati.join(",");
      linhas.push(`[${r.status}] ${r.id}  ${r.severidade}  dor ${dores}  ${r.descricao}`);
      if (r.status !== "CONFORME" && r.status !== "PULADO") {
        if (r.atual !== undefined || r.esperado !== undefined) {
          linhas.push(`    atual: ${r.atual} | esperado: ${r.esperado}`);
        }
        for (const m of r.mudancas) {
          linhas.push(`    alterado: ${m}`);
        }
      }
      if (r.detalhe) {
        linhas.push(`    detalhe: ${r.detalhe}`);
      }
    }

    linhas.push("");
    const resumoStr = Object.entries(dados.resumo)
      .map(([k, v]) => `${k}=${v}`)
      .join(", ") || "nenhuma regra";
    linhas.push(`Resumo (${dados.regras.length} regra(s)): ${resumoStr}`);

    if (Object.keys(dados.por_dor).length > 0) {
      linhas.push("Por dor da ATI:");
      for (const [d, v] of Object.entries(dados.por_dor)) {
        linhas.push(`  Dor ${d} (${v.nome}): ${v.conformes}/${v.total} conformes`);
      }
    }

    return linhas.join("\n") + "\n";
  }

  public codigoSaida(resultados: Resultado[]): number {
    const statusSet = new Set(resultados.map(r => r.status));
    if (statusSet.has("ERRO") || statusSet.has("FALHOU")) {
      return 2;
    }
    if (statusSet.has("NAO_CONFORME") || statusSet.has("SERIA_CORRIGIDO")) {
      return 1;
    }
    return 0;
  }

  // --- OFFBOARDING (DOR 5 DA ATI) ---
  public executarOffboarding(
    autorizadosCsvContent: string,
    aplicar: boolean = false
  ): {
    sucesso: boolean;
    erro?: string;
    autorizados: string[];
    contasNaoAutorizadas: string[];
    acoes: string[];
    mudancas: string[];
    sessaoCriada?: BackupSession;
    modo: string;
  } {
    const modo = aplicar ? "enforce --apply" : "enforce --dry-run";
    this.log(`Iniciando offboarding (--autorizados, modo: ${modo})...`);

    // Parse authorized users from CSV content
    const autorizadosSet = new Set<string>(["root"]);
    const lines = autorizadosCsvContent.split("\n");
    let userColIdx = 0;
    let headerParsed = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      const delim = line.includes(";") && !line.includes(",") ? ";" : ",";
      const parts = line.split(delim).map(p => p.trim());

      if (!headerParsed) {
        headerParsed = true;
        const lower = parts.map(p => p.toLowerCase());
        if (lower.includes("usuario")) userColIdx = lower.indexOf("usuario");
        else if (lower.includes("user")) userColIdx = lower.indexOf("user");
        else if (lower.includes("username")) userColIdx = lower.indexOf("username");
        else {
          userColIdx = 0;
          if (!["usuario", "user", "username", "login"].includes(parts[0].toLowerCase())) {
            autorizadosSet.add(parts[0].toLowerCase());
          }
        }
        continue;
      }

      if (parts[userColIdx]) {
        autorizadosSet.add(parts[userColIdx].toLowerCase());
      }
    }

    const autorizadosList = Array.from(autorizadosSet);

    // Read local accounts from simulated /etc/passwd
    const passwd = this.system.files["/etc/passwd"] || "";
    const contasLocais: Array<{ username: string; uid: number; shell: string; home: string }> = [];

    for (const pLine of passwd.split("\n")) {
      const trimmed = pLine.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const parts = trimmed.split(":");
      if (parts.length >= 7) {
        const username = parts[0];
        const uid = parseInt(parts[2], 10);
        if ((uid >= 1000 || uid === 0) && !["nobody", "nfsnobody"].includes(username)) {
          contasLocais.push({
            username,
            uid,
            shell: parts[6],
            home: parts[5]
          });
        }
      }
    }

    const contasNaoAutorizadas = contasLocais
      .filter(c => !autorizadosSet.has(c.username.toLowerCase()))
      .map(c => c.username);

    const acoes: string[] = [];
    const mudancas: string[] = [];

    if (contasNaoAutorizadas.length === 0) {
      acoes.push("Nenhuma conta não autorizada encontrada no sistema. Todos os usuários locais estão homologados.");
      return {
        sucesso: true,
        autorizados: autorizadosList,
        contasNaoAutorizadas: [],
        acoes,
        mudancas,
        modo
      };
    }

    if (aplicar) {
      const motivoTrava = this.travaVm();
      if (motivoTrava) {
        return {
          sucesso: false,
          erro: motivoTrava,
          autorizados: autorizadosList,
          contasNaoAutorizadas,
          acoes: [`RECUSADO: ${motivoTrava}`],
          mudancas: [],
          modo
        };
      }
    }

    let sessao: BackupSession | null = null;
    if (aplicar) {
      const agora = new Date();
      sessao = {
        id: agora.toISOString().replace(/[-:]/g, "").slice(0, 15) + "-offboarding",
        criadoEm: agora.toISOString(),
        revertida: false,
        entradas: []
      };

      // Backup sensitive files before changing
      for (const arq of ["/etc/passwd", "/etc/shadow", "/etc/group.wheel"]) {
        const existia = this.system.files[arq] !== undefined;
        sessao.entradas.push({
          caminho: arq,
          existia,
          arquivo_backup: `arquivos/${String(sessao.entradas.length + 1).padStart(4, "0")}`,
          regra: "OFF-001",
          servicos: [],
          conteudoOriginal: existia ? this.system.files[arq] : undefined
        });
      }
    }

    for (const user of contasNaoAutorizadas) {
      const descLock = `Bloquear conta '${user}' (usermod -L e chage -E 0)`;
      const descShell = `Alterar shell de '${user}' para /sbin/nologin`;
      const descKeys = `Arquivar chaves ~/.ssh/authorized_keys de '${user}'`;
      const descWheel = `Remover '${user}' do grupo administrativo wheel`;
      const descKill = `Encerrar sessões ativas de '${user}' (pkill -u ${user})`;

      if (!aplicar) {
        acoes.push(`[SERIA_CORRIGIDO] ${descLock}`);
        acoes.push(`[SERIA_CORRIGIDO] ${descShell}`);
        acoes.push(`[SERIA_CORRIGIDO] ${descKeys}`);
        acoes.push(`[SERIA_CORRIGIDO] ${descWheel}`);
        acoes.push(`[SERIA_CORRIGIDO] ${descKill}`);
      } else {
        // 1 & 2: Update /etc/passwd and locked accounts
        let updatedPasswd = this.system.files["/etc/passwd"] || "";
        const pLines = updatedPasswd.split("\n").map(l => {
          if (l.startsWith(`${user}:`)) {
            const p = l.split(":");
            p[6] = "/sbin/nologin";
            return p.join(":");
          }
          return l;
        });
        this.system.files["/etc/passwd"] = pLines.join("\n");

        const locked = (this.system.files["/var/lib/hardener/locked_accounts"] || "").split(",").filter(Boolean);
        if (!locked.includes(user)) locked.push(user);
        this.system.files["/var/lib/hardener/locked_accounts"] = locked.join(",");

        // 3: Revoke keys
        this.system.files["/var/lib/hardener/revoked_keys"] = "true";

        // 4: Remove from wheel
        let wheel = (this.system.files["/etc/group.wheel"] || "root,admin_ati,estagiario").split(",");
        wheel = wheel.filter(m => m !== user);
        this.system.files["/etc/group.wheel"] = wheel.join(",");

        mudancas.push(`Conta '${user}' bloqueada com chage -E 0 e usermod -L`);
        mudancas.push(`Shell de '${user}' alterado para /sbin/nologin`);
        mudancas.push(`Chaves SSH de '${user}' arquivadas em /var/backups/revoked_ssh_keys/`);
        mudancas.push(`'${user}' removido do grupo wheel`);
        mudancas.push(`Sessões ativas de '${user}' finalizadas`);
      }
    }

    if (aplicar && sessao) {
      this.backups.unshift(sessao);
      acoes.push(`Sessão de backup ${sessao.id} gerada com sucesso.`);
    }

    return {
      sucesso: true,
      autorizados: autorizadosList,
      contasNaoAutorizadas,
      acoes,
      mudancas,
      sessaoCriada: sessao || undefined,
      modo
    };
  }

  private log(msg: string) {
    const time = new Date().toLocaleTimeString();
    this.executionLog.push(`[${time}] ${msg}`);
  }
}
