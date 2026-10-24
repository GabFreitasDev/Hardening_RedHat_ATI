# Fila de validação na VM

O que depende do sistema real não pode ser provado pelos testes unitários. Quem escreve a regra
acrescenta o item aqui; quem hospeda a VM executa em lote, marca o resultado e commita.

Antes de começar: snapshot `base-limpa` feito, segunda sessão SSH aberta, `/etc/hardener-vm` criado
(ver `docs/AMBIENTE_VM.md`).

## Pendentes: núcleo e SSH-001

- [ ] `python3 --version` na VM é 3.9.x e `python3 -c "import yaml"` funciona.
- [ ] `sudo python3 -m hardener validar` passa na VM.
- [ ] `/etc/os-release` do Rocky/Alma/RHEL 9 é reconhecido: o relatório mostra `plataforma: rhel9`.
- [ ] `sudo sshd -T` funciona e imprime `permitrootlogin yes` (ou o valor padrão da VM).
- [ ] `grep -n Include /etc/ssh/sshd_config` mostra `Include /etc/ssh/sshd_config.d/*.conf` **antes** de
      qualquer `PermitRootLogin` no arquivo. Se não mostrar, o `00-hardener.conf` não tem efeito.
- [ ] Depois do `enforce --apply`: `sudo sshd -T | grep -i permitrootlogin` mostra `no`, mesmo com
      `50-redhat.conf` (e `50-cloud-init.conf`, se existir) presentes em `/etc/ssh/sshd_config.d/`.
- [ ] `sudo systemctl reload sshd` funciona com esse nome de unidade; a sessão SSH aberta sobrevive.
- [ ] Sintaxe quebrada de propósito (ex.: linha inválida em `00-hardener.conf`): `enforce --apply` reverte
      e **não** recarrega (testar o caminho de falha).
- [ ] `sudo python3 -m hardener rollback` remove `00-hardener.conf` (que não existia antes) e o
      `sshd -T` volta ao valor anterior.
- [ ] Segundo `enforce --apply` seguido: tudo `CONFORME`, sem nova pasta em `/var/lib/hardener/backups/`.
- [ ] Sem o arquivo `/etc/hardener-vm`, `enforce --apply` é recusado; como usuário comum (sem `sudo`), também.
- [ ] OpenSCAP: confirmar o arquivo de conteúdo e o id do perfil CIS com `oscap info` e anotar abaixo.

## Modelo para cada regra nova

```
- [ ] <ID> audit reprova na VM suja
- [ ] <ID> enforce --apply corrige (relatório mostra CORRIGIDO)
- [ ] <ID> segundo enforce --apply não altera nada
- [ ] <ID> rollback restaura o estado anterior
- [ ] <ID> nenhum serviço legítimo quebrou (SELinux/audit.log, sessão SSH, firewall)
```

## Anotações da VM

- Distribuição e versão: _
- Arquivo/perfil OpenSCAP confirmado: _
- Problemas encontrados: _
