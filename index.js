/**
 * SYSACK — Cloud Functions Firebase
 * functions/src/index.js
 *
 * Funções:
 *   alertaMaquinaOffline                  — schedule 6h
 *   verificarPrazosSchedule               — schedule 8h diário
 *   buscarEmpregados                      — callable
 *   getEmpregadoStatus                    — callable
 *   registrarMetricaCliente               — HTTP
 *   pegarComandoPendente                  — HTTP
 *   enviarConfirmacaoChamado              — callable
 *   notificarGestorAprovacao              — callable
 *   notificarDecisaoAprovacao             — callable
 *   renotificarGestorAprovacoesPendentes  — callable
 *   alertarPrazoTerceirizada              — callable
 *   executarComandoMDM                    — callable
 *   getHistoricoUsuarios                  — callable
 *   getHistoricoAtivo                     — callable
 *   adicionarNotaHistorico                — callable
 *   triageChamado                         — callable (Gemini)
 *   getInsightsIA                         — callable (Gemini)
 *   analisarAtivo                         — callable (Gemini)
 */

'use strict';

const { initializeApp }            = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const { onSchedule }               = require('firebase-functions/v2/scheduler');
const { onCall, HttpsError, onRequest } = require('firebase-functions/v2/https');
const { onDocumentUpdated, onDocumentCreated } = require('firebase-functions/v2/firestore');
const { defineSecret }             = require('firebase-functions/params');

// ── Secrets (devem ser declarados antes das funções) ──────────────────────
const GEMINI_KEY  = defineSecret('GOOGLE_GENAI_API_KEY');
const SMTP_HOST_S = defineSecret('SMTP_HOST');
const SMTP_PORT_S = defineSecret('SMTP_PORT');
const SMTP_USER_S = defineSecret('SMTP_USER');
const SMTP_PASS_S = defineSecret('SMTP_PASS');
const SMTP_FROM_S = defineSecret('SMTP_FROM');
const ALL_SECRETS = [GEMINI_KEY, SMTP_HOST_S, SMTP_PORT_S, SMTP_USER_S, SMTP_PASS_S, SMTP_FROM_S];
const https                        = require('https');

initializeApp();
const db     = getFirestore();
const REGION = 'us-central1';

// ─── UTILITÁRIOS ─────────────────────────────────────────────────

function validarAgentId(id) {
  if (!id || typeof id !== 'string') return false;
  return /^[a-zA-Z0-9_-]{1,128}$/.test(id);
}

function san(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '').slice(0, maxLen);
}

function esc(s) {
  return String(s || '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function getGestorEmails() {
  try {
    const snap = await db.collection('users')
      .where('role', 'in', ['admin', 'gestor'])
      .where('ativo', '==', true).get();
    return snap.docs.map(d => d.data().email)
      .filter(e => typeof e === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e));
  } catch { return []; }
}

async function getTecnicoEmail(tecnicoId) {
  if (!tecnicoId) return null;
  try {
    const s = await db.collection('tecnicos').doc(tecnicoId).get();
    return s.exists ? (s.data().email || null) : null;
  } catch { return null; }
}

// ─── EMAIL ───────────────────────────────────────────────────────

async function sendEmail(para, assunto, htmlBody) {
  // Tenta secrets primeiro, depois env vars (fallback para dev local)
  const host = (trySecret(SMTP_HOST_S) || process.env.SMTP_HOST || '').trim();
  const user = (trySecret(SMTP_USER_S) || process.env.SMTP_USER || '').trim();
  const pass = (trySecret(SMTP_PASS_S) || process.env.SMTP_PASS || '').trim();
  const from = (trySecret(SMTP_FROM_S) || process.env.SMTP_FROM || 'sysack@cesan.com.br').trim();
  const port = parseInt(trySecret(SMTP_PORT_S) || process.env.SMTP_PORT || '587');

  if (!host || !user || !pass) {
    await db.collection('emails_pendentes').add({
      para, assunto, htmlBody,
      criadoEm: FieldValue.serverTimestamp(), enviado: false,
    });
    console.log(`[email] Enfileirado (sem SMTP): ${assunto} → ${para}`);
    return false;
  }
  try {
    const nodemailer = require('nodemailer');
    const t = nodemailer.createTransport({
      host, port, secure: port === 465,
      auth: { user, pass },
      tls: { rejectUnauthorized: false }, // aceita cert auto-assinado corporativo
    });
    await t.verify(); // testa conexão antes de enviar
    await t.sendMail({ from, to: para, subject: assunto, html: htmlBody });
    console.log(`[email] Enviado: ${assunto} → ${para}`);
    return true;
  } catch (e) {
    console.error('[email] Falha ao enviar:', e.message);
    // Enfileira para retry posterior
    await db.collection('emails_pendentes').add({
      para, assunto, htmlBody,
      criadoEm: FieldValue.serverTimestamp(), enviado: false, erro: e.message,
    }).catch(()=>{});
    return false;
  }
}

// Helper seguro para ler secrets (retorna null se não disponível)
function trySecret(secret) {
  try { return secret && secret.value ? secret.value() : null; } catch { return null; }
}

function emailHtml(titulo, corpo, cor = '#2563EB') {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Arial,sans-serif;background:#F1F5F9;margin:0;padding:20px}
.c{background:#fff;border-radius:12px;max-width:600px;margin:0 auto;overflow:hidden;box-shadow:0 4px 16px rgba(0,0,0,.08)}
.h{background:${esc(cor)};color:#fff;padding:24px 28px}
.h h1{margin:0;font-size:20px;font-weight:700}
.h p{margin:4px 0 0;font-size:13px;opacity:.8}
.b{padding:24px 28px}
.btn{display:inline-block;background:${esc(cor)};color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600;margin-top:16px}
table{width:100%;border-collapse:collapse;margin:16px 0}
td,th{padding:10px 12px;font-size:13px;border-bottom:1px solid #E2E8F0;text-align:left}
th{background:#F8FAFC;font-weight:600;color:#64748B;font-size:11px;text-transform:uppercase}
.f{padding:16px 28px;font-size:11px;color:#94A3B8;border-top:1px solid #E2E8F0}
</style></head><body>
<div class="c">
  <div class="h"><h1>🖥️ SYSACK</h1><p>${esc(titulo)}</p></div>
  <div class="b">${corpo}</div>
  <div class="f">SYSACK · A-DSI · CESAN — Sistema de Gestão de Ativos de TI · E-mail automático, não responda.</div>
</div></body></html>`;
}

// ─── SCHEDULE: MÁQUINAS OFFLINE ──────────────────────────────────

exports.alertaMaquinaOffline = onSchedule(
  { schedule: 'every 6 hours', region: REGION, timeoutSeconds: 300, memory: '256MiB', secrets: ALL_SECRETS },
  async () => {
    const DIAS   = 5;
    const agora  = new Date();
    const limite = new Date(agora.getTime() - DIAS * 86400000);
    const emails  = await getGestorEmails();
    const alertas = [];

    const snap = await db.collection('ativos')
      .where('tipo', 'in', ['computador','notebook','workstation'])
      .where('status', '==', 'ativo').get();

    for (const doc of snap.docs) {
      const a  = doc.data();
      if (!a.lastSeen) continue;
      const ls = a.lastSeen?.toDate?.() || new Date(a.lastSeen);
      if (isNaN(ls.getTime()) || ls >= limite) continue;
      const dias = Math.floor((agora - ls) / 86400000);
      const mat  = a.matriculaResp || a.mat;
      if (mat) {
        try {
          const e = await db.doc(`empregados/${mat}`).get();
          if (e.exists && e.data().suprimirAlertas) continue;
        } catch {}
      }
      alertas.push({ pat: san(a.pat||doc.id), desc: san(a.desc||'—'), resp: san(a.resp||'—'), area: san(a.area||'—'), dias, lastSeen: ls.toLocaleDateString('pt-BR') });
    }

    if (alertas.length && emails.length) {
      const rows = alertas.map(a =>
        `<tr><td>${esc(a.pat)}</td><td>${esc(a.desc)}</td><td>${esc(a.area)}</td><td>${esc(a.resp)}</td><td><b>${a.dias}d</b></td><td>${esc(a.lastSeen)}</td></tr>`
      ).join('');
      const corpo = `<p>As máquinas abaixo não fizeram contato há mais de <strong>${DIAS} dias</strong>.</p>
<table><thead><tr><th>PAT</th><th>Descrição</th><th>Área</th><th>Resp.</th><th>Offline</th><th>Último contato</th></tr></thead>
<tbody>${rows}</tbody></table>
<a href="https://sysack.vercel.app/" class="btn">Abrir SYSACK</a>`;
      await sendEmail(emails.join(','), `[SYSACK] ${alertas.length} máquina(s) offline há mais de ${DIAS} dias`, emailHtml(`${alertas.length} máquina(s) offline`, corpo, '#DC2626'));
    }
    console.log(`[alertaMaquinaOffline] ${alertas.length} alertas`);
  }
);

// ─── SCHEDULE: PRAZOS TERCEIRIZADA ───────────────────────────────

exports.verificarPrazosSchedule = onSchedule(
  { schedule: 'every day 08:00', region: REGION, timeZone: 'America/Sao_Paulo', timeoutSeconds: 120, memory: '256MiB', secrets: ALL_SECRETS },
  async () => {
    const hoje  = new Date(); hoje.setHours(0,0,0,0);
    const emails = await getGestorEmails();
    const snap   = await db.collection('terceirizadaAtivos').where('retornado','==',false).get();
    const vencidos = [];

    for (const doc of snap.docs) {
      const t    = doc.data();
      if (!t.prazoRetorno) continue;
      const venc = new Date(t.prazoRetorno); venc.setHours(0,0,0,0);
      const diff = Math.round((venc - hoje) / 86400000);

      if (diff === 5 && !t._alerta5dEnviado) {
        const tecEmail = await getTecnicoEmail(t.tecnicoId);
        const corpo5 = `<p>O equipamento abaixo deve ser devolvido à <strong>A-DSI em 5 dias úteis</strong>.</p>
<table><tr><th>Patrimônio</th><td><b>${esc(t.pat||t.ativo||'—')}</b></td></tr>
<tr><th>Prazo</th><td><b>${esc(t.prazoRetorno)}</b></td></tr>
<tr><th>Chamado</th><td>${esc(t.chamadoId||'—')}</td></tr></table>
<a href="https://sysack.vercel.app/" class="btn">Registrar retorno no SYSACK</a>`;
        const dest = [tecEmail, ...emails].filter(Boolean).join(',');
        if (dest) await sendEmail(dest, `[SYSACK] ⚠️ Devolução pendente — ${t.pat||t.ativo} — 5 dias`, emailHtml('Prazo de devolução se aproximando', corpo5, '#D97706'));
        await doc.ref.update({ _alerta5dEnviado: true });
      }

      if (diff < 0) vencidos.push({ pat: t.pat||t.ativo||'—', dias: -diff, prazo: t.prazoRetorno, chamado: t.chamadoId||'—' });
    }

    if (vencidos.length && emails.length) {
      const rows = vencidos.map(v => `<tr><td>${esc(v.pat)}</td><td>${esc(v.chamado)}</td><td style="color:#DC2626;font-weight:700">${v.dias}d em atraso</td><td>${esc(v.prazo)}</td></tr>`).join('');
      const corpo = `<p><strong>${vencidos.length} equipamento(s)</strong> com prazo de devolução vencido.</p>
<table><thead><tr><th>Patrimônio</th><th>Chamado</th><th>Atraso</th><th>Prazo era</th></tr></thead>
<tbody>${rows}</tbody></table>
<a href="https://sysack.vercel.app/" class="btn">Ver Terceirizada no SYSACK</a>`;
      await sendEmail(emails.join(','), `[SYSACK] 🚨 ${vencidos.length} equipamento(s) com prazo vencido na terceirizada`, emailHtml('Prazo vencido', corpo, '#DC2626'));
    }

    console.log(`[verificarPrazosSchedule] ${vencidos.length} vencidos`);
  }
);

// ─── CALLABLE: BUSCAR EMPREGADOS ─────────────────────────────────

exports.buscarEmpregados = onCall(
  { enforceAppCheck: false, region: REGION },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { termo, setor, apenasAtivos = true } = req.data || {};
    if (termo !== undefined && typeof termo !== 'string') throw new HttpsError('invalid-argument', 'termo deve ser string');
    if (setor !== undefined && typeof setor !== 'string') throw new HttpsError('invalid-argument', 'setor deve ser string');

    let query = db.collection('empregados');
    if (apenasAtivos) query = query.where('ativo', '==', true);
    if (setor) query = query.where('setor', '==', setor);
    const snap = await query.orderBy('nome').limit(50).get();
    const t    = termo?.toLowerCase();
    return snap.docs.map(d => d.data())
      .filter(e => !t || e.nome?.toLowerCase().includes(t) || e.mat?.includes(t))
      .map(e => ({ mat: e.mat||'', nome: e.nome||'', setor: e.setor||'', cargo: e.cargo||'', email: e.email||'', emAusencia: e.emAusencia||false, ausencia: e.ausencia||'' }));
  }
);

// ─── CALLABLE: STATUS EMPREGADO ──────────────────────────────────

exports.getEmpregadoStatus = onCall(
  { enforceAppCheck: false, region: REGION },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { matricula } = req.data || {};
    if (!matricula) throw new HttpsError('invalid-argument', 'matricula é obrigatória');
    const id   = String(matricula).replace(/[^a-zA-Z0-9_-]/g,'').slice(0,50);
    const snap = await db.doc(`empregados/${id}`).get();
    if (!snap.exists) return { encontrado: false };
    const e = snap.data();
    return {
      encontrado: true, mat: e.mat||'', nome: e.nome||'', setor: e.setor||'',
      cargo: e.cargo||'', email: e.email||'', emAusencia: e.emAusencia||false,
      ausencia: e.ausencia||'', suprimirAlertas: e.suprimirAlertas||false,
      dataFimAusencia: e.dataFimAusencia||'', ativo: e.ativo !== false,
    };
  }
);

// ─── HTTP: MÉTRICAS DO CLIENTE ────────────────────────────────────

exports.registrarMetricaCliente = onRequest(
  { region: REGION, cors: true },
  async (req, res) => {
    if (req.method !== 'POST') { res.status(405).send('Method Not Allowed'); return; }
    const agentId = req.headers['x-agent-id'] || '';
    const payload = req.body;
    if (!validarAgentId(agentId)) { res.status(400).json({ erro: 'x-agent-id inválido' }); return; }
    if (!payload || typeof payload !== 'object') { res.status(400).json({ erro: 'payload inválido' }); return; }
    try {
      const m = {
        agentId,
        hostname:  typeof payload.hostname  === 'string' ? payload.hostname.slice(0,200)  : null,
        cpuPct:    typeof payload.cpuPct    === 'number' ? payload.cpuPct                  : null,
        ramPct:    typeof payload.ramPct    === 'number' ? payload.ramPct                  : null,
        diskCPct:  typeof payload.diskCPct  === 'number' ? payload.diskCPct                : null,
        uptimeH:   typeof payload.uptimeH   === 'number' ? payload.uptimeH                 : null,
        latencyMs: typeof payload.latencyMs === 'number' ? payload.latencyMs               : null,
        ipAddress: typeof payload.ipAddress === 'string' ? payload.ipAddress.slice(0,50)   : null,
        recebidoEm: FieldValue.serverTimestamp(),
      };
      await db.collection('metricas').doc(agentId).set(m, { merge: true });

      if (payload.pat) {
        const as = await db.collection('ativos').where('pat','==', String(payload.pat).slice(0,100)).limit(1).get();
        if (!as.empty) await as.docs[0].ref.update({ lastSeen: FieldValue.serverTimestamp() });
      }

      const alertas = [];
      if ((m.cpuPct   ?? 0) >= 90) alertas.push(`CPU crítica: ${m.cpuPct}%`);
      if ((m.ramPct   ?? 0) >= 90) alertas.push(`RAM crítica: ${m.ramPct}%`);
      if ((m.diskCPct ?? 0) >= 90) alertas.push(`Disco crítico: ${m.diskCPct}%`);
      res.json({ ok: true, alertas: alertas.length, msgs: alertas });
    } catch (e) { console.error('[metrica]', e.message); res.status(500).json({ erro: 'Erro interno' }); }
  }
);

// ─── HTTP: PEGAR COMANDO DO AGENTE ───────────────────────────────

exports.pegarComandoPendente = onRequest(
  { region: REGION, cors: false },
  async (req, res) => {
    const agentId = req.query.agentId || '';
    if (!validarAgentId(agentId)) { res.json({ comando: null }); return; }
    try {
      const snap = await db.collection('agent_commands')
        .where('agentId','==', agentId)
        .where('executado','==', false)
        .orderBy('criadoEm','asc').limit(1).get();
      if (snap.empty) { res.json({ comando: null }); return; }
      const doc = snap.docs[0];
      await doc.ref.update({ executado: true, executadoEm: FieldValue.serverTimestamp() });
      const cmd = doc.data();
      res.json({ comando: { id: doc.id, tipo: cmd.tipo||'', payload: cmd.payload||{} } });
    } catch (e) { console.error('[cmdPendente]', e.message); res.json({ comando: null }); }
  }
);

// ─── CALLABLE: CONFIRMAÇÃO DE CHAMADO ────────────────────────────

exports.enviarConfirmacaoChamado = onCall(
  { enforceAppCheck: false, region: REGION, secrets: ALL_SECRETS },
  async req => {
    // Permite sem auth — confirmação de chamado não expõe dados sensíveis
    const { chamadoId, titulo, solicitante, prioridade, email } = req.data || {};
    if (!chamadoId || !email) return { enviado: false };
    const corpo = `<p>Olá, <strong>${esc(solicitante||'usuário')}</strong>! Seu chamado foi registrado com sucesso.</p>
<table>
<tr><th>Número</th><td><strong>${esc(chamadoId)}</strong></td></tr>
<tr><th>Descrição</th><td>${esc(titulo||'—')}</td></tr>
<tr><th>Prioridade</th><td>${esc(prioridade||'Normal')}</td></tr>
<tr><th>Status</th><td>Aberto — aguardando atendimento</td></tr>
</table>
<a href="https://sysack.vercel.app/" class="btn">Acompanhar no SYSACK</a>`;
    const ok = await sendEmail(email, `[SYSACK] Chamado ${chamadoId} registrado`, emailHtml(`Chamado ${chamadoId}`, corpo));
    return { enviado: ok };
  }
);

// ─── HTTP: enviarConfirmacaoChamado (para fetch sem token Firebase) ─
exports.enviarConfirmacaoChamadoHttp = onRequest(
  { region: REGION, cors: true, secrets: ALL_SECRETS },
  async (req, res) => {
    if (req.method !== 'POST') return res.status(405).send('Method Not Allowed');
    const body = req.body?.data || req.body || {};
    const { chamadoId, titulo, solicitante, prioridade, email } = body;
    if (!chamadoId || !email) return res.json({ enviado: false, erro: 'Dados incompletos' });
    const corpo = `<p>Olá, <strong>${esc(solicitante||'usuário')}</strong>! Seu chamado foi registrado com sucesso.</p>
<table>
<tr><th>Número</th><td><strong>${esc(chamadoId)}</strong></td></tr>
<tr><th>Descrição</th><td>${esc(titulo||'—')}</td></tr>
<tr><th>Prioridade</th><td>${esc(prioridade||'Normal')}</td></tr>
<tr><th>Status</th><td>Aberto — aguardando atendimento</td></tr>
</table>
<a href="https://sysack.vercel.app/" class="btn">Acompanhar no SYSACK</a>`;
    const ok = await sendEmail(email, `[SYSACK] Chamado ${chamadoId} registrado`, emailHtml(`Chamado ${chamadoId}`, corpo));
    res.json({ enviado: ok });
  }
);

// ─── SCHEDULE: PROCESSAR FILA DE E-MAILS PENDENTES ─────────────────────
// Roda a cada 5 minutos e tenta reenviar e-mails que falharam anteriormente.

exports.processarEmailsPendentes = onSchedule(
  { schedule: 'every 5 minutes', region: REGION, timeoutSeconds: 120,
    memory: '256MiB', secrets: ALL_SECRETS },
  async () => {
    const snap = await db.collection('emails_pendentes')
      .where('enviado', '==', false)
      .orderBy('criadoEm', 'asc')
      .limit(20).get();

    if (snap.empty) { console.log('[emailQueue] Nenhum e-mail pendente.'); return; }

    console.log(`[emailQueue] Processando ${snap.size} e-mail(s) pendente(s)...`);
    let enviados = 0;

    for (const doc of snap.docs) {
      const { para, assunto, htmlBody } = doc.data();
      try {
        const ok = await sendEmail(para, assunto, htmlBody);
        if (ok) {
          await doc.ref.update({ enviado: true, enviadoEm: FieldValue.serverTimestamp() });
          enviados++;
          console.log(`[emailQueue] ✓ Enviado: ${assunto} → ${para}`);
        }
      } catch (e) {
        console.error(`[emailQueue] Falha: ${assunto} → ${para}: ${e.message}`);
        await doc.ref.update({ ultimoErro: e.message, tentativas: FieldValue.increment(1) })
          .catch(()=>{});
      }
    }
    console.log(`[emailQueue] Concluído: ${enviados}/${snap.size} enviados.`);
  }
);

// ─── CALLABLE: NOTIFICAR GESTOR (NOVA APROVAÇÃO) ─────────────────

exports.notificarGestorAprovacao = onCall(
  { enforceAppCheck: false, region: REGION, secrets: ALL_SECRETS },
  async req => {
    // Permite sem auth — notificação de aprovação
    const { aprovacaoId, tipo, pat, solicitante, gestorEmail } = req.data || {};
    if (!aprovacaoId) return { enviado: false };
    const emails = gestorEmail ? [gestorEmail] : await getGestorEmails();
    if (!emails.length) return { enviado: false };
    const corpo = `<p>Uma movimentação de patrimônio aguarda sua autorização.</p>
<table>
<tr><th>Tipo</th><td>${esc(tipo||'—')}</td></tr>
<tr><th>Patrimônio</th><td><strong>${esc(pat||'—')}</strong></td></tr>
<tr><th>Solicitado por</th><td>${esc(solicitante||'—')}</td></tr>
</table>
<p>⚠️ O fluxo está <strong>pausado</strong> até sua decisão.</p>
<a href="https://sysack.vercel.app/" class="btn">Aprovar no SYSACK</a>`;
    const ok = await sendEmail(emails.join(','), `[SYSACK] ⏳ Aprovação pendente — ${tipo||'Movimentação'} — PAT: ${pat||'—'}`, emailHtml('Aprovação pendente', corpo, '#D97706'));
    return { enviado: ok, destinatarios: emails };
  }
);

// ─── CALLABLE: NOTIFICAR DECISÃO DA APROVAÇÃO ────────────────────

exports.notificarDecisaoAprovacao = onCall(
  { enforceAppCheck: false, region: REGION, secrets: ALL_SECRETS },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { aprovacaoId, decisao, pat, tipo, solicitante, decidedBy } = req.data || {};
    if (!aprovacaoId) return { enviado: false };

    let emailDestino = '';
    try {
      const snap = await db.collection('aprovacoes').doc(aprovacaoId).get();
      if (snap.exists) {
        const sid = snap.data().solicitanteId;
        if (sid) { const u = await db.collection('users').doc(sid).get(); if (u.exists) emailDestino = u.data().email || ''; }
      }
    } catch {}
    if (!emailDestino) return { enviado: false };

    const ok   = decisao === 'aprovado';
    const cor  = ok ? '#059669' : '#DC2626';
    const txt  = ok ? 'AUTORIZADA ✅' : 'RECUSADA ❌';
    const corpo = `<p>A movimentação que você solicitou foi <strong style="color:${cor}">${txt}</strong> pelo gestor.</p>
<table>
<tr><th>Tipo</th><td>${esc(tipo||'—')}</td></tr>
<tr><th>Patrimônio</th><td><strong>${esc(pat||'—')}</strong></td></tr>
<tr><th>Decisão</th><td style="color:${cor};font-weight:700">${txt}</td></tr>
<tr><th>Decidido por</th><td>${esc(decidedBy||'Gestor')}</td></tr>
</table>
${ok ? '<p>O fluxo foi retomado.</p>' : '<p>Entre em contato com o gestor para mais informações.</p>'}
<a href="https://sysack.vercel.app/" class="btn">Ver no SYSACK</a>`;
    const enviado = await sendEmail(emailDestino, `[SYSACK] Movimentação ${txt} — PAT: ${pat||'—'}`, emailHtml(`Movimentação ${txt}`, corpo, cor));
    return { enviado };
  }
);

// ─── CALLABLE: RE-ALERTAR GESTOR (APROVAÇÕES URGENTES) ───────────

exports.renotificarGestorAprovacoesPendentes = onCall(
  { enforceAppCheck: false, region: REGION, secrets: ALL_SECRETS },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { urgentes, gestorEmail, itens = [] } = req.data || {};
    if (!urgentes) return { enviado: false };
    const emails = gestorEmail ? [gestorEmail] : await getGestorEmails();
    if (!emails.length) return { enviado: false };
    const rows = itens.map(a =>
      `<tr><td>${esc(a.tipo||'—')}</td><td>${esc(a.pat||'—')}</td><td style="color:#DC2626;font-weight:700">${a.dias} dia(s)</td></tr>`
    ).join('');
    const corpo = `<p>⚠️ <strong>${urgentes} aprovação(ões) urgentes</strong> aguardando decisão há mais de 1 dia.</p>
${rows ? `<table><thead><tr><th>Tipo</th><th>Patrimônio</th><th>Aguardando</th></tr></thead><tbody>${rows}</tbody></table>` : ''}
<p>O fluxo está <strong>bloqueado</strong>. Por favor acesse o SYSACK.</p>
<a href="https://sysack.vercel.app/" class="btn">Ver Aprovações Pendentes</a>`;
    const ok = await sendEmail(emails.join(','), `[SYSACK] 🚨 ${urgentes} aprovação(ões) urgentes pendentes`, emailHtml('Aprovações urgentes', corpo, '#DC2626'));
    return { enviado: ok };
  }
);

// ─── CALLABLE: ALERTAR PRAZO TERCEIRIZADA ────────────────────────

exports.alertarPrazoTerceirizada = onCall(
  { enforceAppCheck: false, region: REGION, secrets: ALL_SECRETS },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { tercId, pat, prazoRetorno, diasRestantes, tecnicoEmail, tecnicoNome, gestorEmail, chamadoId } = req.data || {};
    if (!tercId) return { enviado: false };

    const vencido = diasRestantes <= 0;
    const cor     = vencido ? '#DC2626' : '#D97706';

    // Alerta ao técnico externo (só quando faltam 5 dias)
    if (!vencido && tecnicoEmail) {
      const corpo = `<p>Olá, <strong>${esc(tecnicoNome||'técnico')}</strong>!
O equipamento abaixo deve ser devolvido à A-DSI em <strong>5 dias úteis</strong>.</p>
<table>
<tr><th>Patrimônio</th><td><strong>${esc(pat||'—')}</strong></td></tr>
<tr><th>Prazo de retorno</th><td><b>${esc(prazoRetorno||'—')}</b></td></tr>
<tr><th>Chamado</th><td>${esc(chamadoId||'—')}</td></tr>
</table>
<a href="https://sysack.vercel.app/" class="btn">Registrar retorno no SYSACK</a>`;
      await sendEmail(tecnicoEmail, `[SYSACK] ⚠️ Devolução pendente — ${pat||'—'} — 5 dias`, emailHtml('Prazo de devolução', corpo, cor));
    }

    // Notifica gestores
    const emails = gestorEmail ? [gestorEmail] : await getGestorEmails();
    if (emails.length) {
      const tempo = vencido
        ? `<strong style="color:#DC2626">VENCIDO há ${-diasRestantes} dia(s)</strong>`
        : `Faltam <strong>${diasRestantes} dias</strong>`;
      const corpo = `<p>${vencido ? '🚨' : '⚠️'} Alerta de prazo — empresa terceirizada.</p>
<table>
<tr><th>Patrimônio</th><td><strong>${esc(pat||'—')}</strong></td></tr>
<tr><th>Prazo</th><td>${esc(prazoRetorno||'—')}</td></tr>
<tr><th>Status</th><td>${tempo}</td></tr>
<tr><th>Técnico</th><td>${esc(tecnicoNome||'—')}</td></tr>
<tr><th>Chamado</th><td>${esc(chamadoId||'—')}</td></tr>
</table>
<a href="https://sysack.vercel.app/" class="btn">Ver Terceirizada</a>`;
      await sendEmail(emails.join(','), vencido ? `[SYSACK] 🚨 PRAZO VENCIDO — ${pat||'—'}` : `[SYSACK] ⚠️ ${pat||'—'} — 5 dias para devolução`, emailHtml('Prazo terceirizada', corpo, cor));
    }

    return { enviado: true };
  }
);

// ─── CALLABLE: EXECUTAR COMANDO MDM ──────────────────────────────

exports.executarComandoMDM = onCall(
  { enforceAppCheck: false, region: REGION },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { smId, imei, tipo, motivo, tecnico, tecnicoId } = req.data || {};
    if (!smId || !tipo) throw new HttpsError('invalid-argument', 'smId e tipo são obrigatórios');

    const TIPOS_OK = ['localize','remote-access','lock','unlock','factory-reset','inventory','geohistory','push-app','remove-app','password-policy'];
    if (!TIPOS_OK.includes(tipo)) throw new HttpsError('invalid-argument', `Tipo MDM não permitido: ${tipo}`);

    // Log imutável da ação MDM
    const logRef = await db.collection('mdm_actions').add({
      smId:      san(smId), imei: san(imei||''), tipo,
      motivo:    san(motivo||'', 1000), tecnico: san(tecnico||''),
      tecnicoId: san(tecnicoId||''), status: 'pendente',
      criadoEm:  FieldValue.serverTimestamp(), uid: req.auth.uid,
    });

    // Cria comando para o dispositivo executar ao reconectar
    await db.collection('agent_commands').add({
      agentId:     san(smId),
      tipo:        'mdm_' + tipo,
      payload:     { imei: san(imei||''), motivo: san(motivo||'') },
      executado:   false,
      criadoEm:    FieldValue.serverTimestamp(),
      mdmActionId: logRef.id,
    });

    console.log(`[MDM] ${tipo} em ${smId} por ${tecnico}`);
    return { status: 'enviado', mdmActionId: logRef.id };
  }
);


function tsToIso(v) {
  return v?.toDate?.()?.toISOString?.() || v || null;
}
function dataDoc(v) {
  const d = v?.toDate?.() || (v ? new Date(v) : null);
  return d && !isNaN(d.getTime()) ? d : null;
}
function contarDiasNoPeriodo(dias = [], inicio, fim) {
  return (dias || []).filter(x => {
    const d = new Date(x);
    return !isNaN(d.getTime()) && (!inicio || d >= inicio) && (!fim || d <= fim);
  }).length;
}
function contarDiasNoAno(dias = [], ano = new Date().getFullYear()) {
  return (dias || []).filter(x => String(x).slice(0,4) === String(ano)).length;
}

// ─── CALLABLE: BUSCAR MÁQUINAS POR HISTÓRICO DE LOGIN DO USUÁRIO ─────────
exports.getAtivosDoUsuario = onCall(
  { enforceAppCheck: false, region: REGION },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { q, mat, login, de, ate, desde } = req.data || {};
    const termo = san(q || mat || login || '', 120).trim().toLowerCase();
    if (!termo) throw new HttpsError('invalid-argument', 'Informe login, matrícula ou nome');

    const inicio = de ? new Date(de + 'T00:00:00') : (desde ? new Date(desde) : null);
    const fim    = ate ? new Date(ate + 'T23:59:59') : null;
    const now    = new Date();
    const d7     = new Date(now.getTime() - 7*86400000);
    const d30    = new Date(now.getTime() - 30*86400000);
    const d365   = new Date(now.getTime() - 365*86400000);

    // Consulta ampla por loginNorm; se não vier nada, faz fallback por mat/nome em até 500 docs.
    let docs = [];
    try {
      const snap = await db.collectionGroup('usuarios_historico').where('loginNorm','==',termo).limit(200).get();
      docs = snap.docs;
    } catch {}
    if (!docs.length) {
      const snap = await db.collectionGroup('usuarios_historico').limit(500).get();
      docs = snap.docs.filter(d => {
        const u = d.data();
        return String(u.loginNorm||u.login||'').toLowerCase().includes(termo) ||
               String(u.mat||'').toLowerCase().includes(termo) ||
               String(u.nome||'').toLowerCase().includes(termo);
      });
    }

    const ativos = [];
    for (const d of docs) {
      const u = d.data();
      const ultimo = dataDoc(u.ultimoLogin || u.ate || u.desde);
      const dias = Array.isArray(u.dias) ? u.dias : [];
      const batePeriodo = (!inicio && !fim) || (ultimo && (!inicio || ultimo >= inicio) && (!fim || ultimo <= fim)) || contarDiasNoPeriodo(dias, inicio, fim) > 0;
      if (!batePeriodo) continue;

      const ativoRef = d.ref.parent.parent;
      if (!ativoRef) continue;
      const aDoc = await ativoRef.get();
      const a = aDoc.exists ? aDoc.data() : {};
      ativos.push({
        ativoId: ativoRef.id,
        pat: a.pat || '', desc: a.desc || '', hostname: a.hostname || '', ip: a.ip || '', area: a.area || '',
        ultimoLogin: ultimo?.toISOString?.() || null,
        totalDias: u.totalDias || dias.length || 0,
        contadorDiasAno: u.contadorDiasAno || contarDiasNoAno(dias),
        dias7: contarDiasNoPeriodo(dias, d7, now),
        dias30: contarDiasNoPeriodo(dias, d30, now),
        dias365: contarDiasNoPeriodo(dias, d365, now),
        ehPrincipal: !!u.ehResponsavel || (Array.isArray(a.usuariosPrincipais) && a.usuariosPrincipais.some(x => (x.loginNorm||x.login||'').toLowerCase() === termo || String(x.mat||'').toLowerCase() === termo)),
        maquinaCompartilhada: !!a.maquinaCompartilhada,
      });
    }

    ativos.sort((a,b) => new Date(b.ultimoLogin||0) - new Date(a.ultimoLogin||0));
    const resumo = {
      ultimoHostname: ativos[0]?.hostname || ativos[0]?.pat || '',
      ultimoLogin: ativos[0]?.ultimoLogin || null,
      semana: ativos.filter(a => a.dias7 > 0).length,
      mes: ativos.filter(a => a.dias30 > 0).length,
      ano: ativos.filter(a => a.dias365 > 0).length,
    };
    return { ativos, resumo };
  }
);

// ─── CALLABLE: HISTÓRICO DE USUÁRIOS DO ATIVO ────────────────────

exports.getHistoricoUsuarios = onCall(
  { enforceAppCheck: false, region: REGION },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { ativoId } = req.data || {};
    if (!ativoId) throw new HttpsError('invalid-argument', 'ativoId é obrigatório');

    const snap = await db.collection('ativos').doc(ativoId)
      .collection('usuarios_historico')
      .orderBy('desde', 'desc').limit(50).get();

    let eventosSnap = { docs: [] };
    try {
      eventosSnap = await db.collection('ativos').doc(ativoId)
        .collection('login_eventos').orderBy('data', 'desc').limit(200).get();
    } catch {}

    return {
      usuarios: snap.docs.map(d => {
        const u = d.data();
        const dias = Array.isArray(u.dias) ? u.dias : [];
        return {
          id: d.id, mat: u.mat||'', nome: u.nome||'', setor: u.setor||'',
          desde:        u.desde?.toDate?.()?.toISOString()  || u.desde || '',
          ate:          u.ate?.toDate?.()?.toISOString()    || u.ate   || null,
          login: u.login || '', loginNorm: u.loginNorm || '',
          ultimoLogin: tsToIso(u.ultimoLogin),
          dias,
          totalDias:    u.totalDias    || dias.length || 0,
          contadorDiasAno: u.contadorDiasAno || contarDiasNoAno(dias),
          dias14: contarDiasNoPeriodo(dias, new Date(Date.now()-14*86400000), new Date()),
          ehResponsavel: u.ehResponsavel || false,
          maquinaCompartilhada: u.maquinaCompartilhada || false,
        };
      }),
      loginEventos: eventosSnap.docs.map(d => {
        const e = d.data();
        return {
          id: d.id, login: e.login || '', loginNorm: e.loginNorm || '', mat: e.mat || '', nome: e.nome || '', setor: e.setor || '',
          data: tsToIso(e.data) || tsToIso(e.timestamp) || tsToIso(e.createdAt),
          desc: e.desc || '',
        };
      }),
    };
  }
);

// ─── CALLABLE: HISTÓRICO DE MOVIMENTAÇÕES DO ATIVO ───────────────

exports.getHistoricoAtivo = onCall(
  { enforceAppCheck: false, region: REGION },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { ativoId, limite = 50 } = req.data || {};
    if (!ativoId) throw new HttpsError('invalid-argument', 'ativoId é obrigatório');

    const snap  = await db.collection('ativos').doc(ativoId)
      .collection('historico')
      .orderBy('data', 'desc').limit(Math.min(Number(limite)||50, 200)).get();

    const ativo  = await db.collection('ativos').doc(ativoId).get();
    const emDoc  = ativo.exists ? (ativo.data().historico || []) : [];

    const fromSub = snap.docs.map(d => {
      const h = d.data();
      return { id: d.id, tipo: h.tipo||'obs', dot: h.dot||'gray', titulo: h.titulo||'', desc: h.desc||'', data: h.data?.toDate?.()?.toISOString() || h.data || '', autor: h.tecnico||h.autor||'' };
    });

    const todos = [...fromSub, ...emDoc.map(h => ({ ...h, data: typeof h.data === 'string' ? h.data : (h.data?.toDate?.()?.toISOString()||'') }))];
    return { historico: todos };
  }
);

// ─── CALLABLE: ADICIONAR NOTA AO HISTÓRICO ───────────────────────

exports.adicionarNotaHistorico = onCall(
  { enforceAppCheck: false, region: REGION },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { ativoId, nota, tipo = 'obs' } = req.data || {};
    if (!ativoId || !nota) throw new HttpsError('invalid-argument', 'ativoId e nota são obrigatórios');

    const TIPOS_OK = ['obs','manutencao','alerta','transferencia','atualizacao'];
    const tipoSafe = TIPOS_OK.includes(tipo) ? tipo : 'obs';
    const dotMap   = { obs:'blue', manutencao:'orange', alerta:'red', transferencia:'violet', atualizacao:'green' };

    const entrada = {
      tipo: tipoSafe, dot: dotMap[tipoSafe]||'blue',
      titulo: tipoSafe === 'obs' ? 'Observação do técnico' : san(tipo, 50),
      desc:   san(nota, 2000), tecnico: san(req.auth.token?.name||req.auth.uid),
      uid:    req.auth.uid, data: FieldValue.serverTimestamp(),
    };

    await db.collection('ativos').doc(ativoId).collection('historico').add(entrada);

    await db.collection('ativos').doc(ativoId).update({
      historico: FieldValue.arrayUnion({
        tipo: entrada.tipo, dot: entrada.dot, titulo: entrada.titulo,
        desc: entrada.desc, tecnico: entrada.tecnico,
        data: new Date().toLocaleDateString('pt-BR'),
      }),
      updatedAt: FieldValue.serverTimestamp(),
    });

    return { ok: true };
  }
);

// ─── CALLABLE: TRIAGEM DE CHAMADO COM IA ─────────────────────────

// secrets declarados no topo do arquivo

// Faz uma tentativa à API Gemini e retorna a Promise
function _geminiRequest(prompt, apiKey, maxTokens) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.2, maxOutputTokens: maxTokens },
    });
    const r = https.request({
      hostname: 'generativelanguage.googleapis.com',
      path:     `/v1beta/models/gemini-2.0-flash-lite:generateContent?key=${apiKey}`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
    }, res => {
      let raw = '';
      res.on('data', chunk => raw += chunk);
      res.on('end', () => {
        if (res.statusCode === 429) { reject(Object.assign(new Error('Gemini 429'), { is429: true })); return; }
        if (res.statusCode !== 200) { reject(new Error(`Gemini ${res.statusCode}`)); return; }
        try { resolve(JSON.parse(raw)); } catch { reject(new Error('JSON inválido')); }
      });
    });
    r.on('error', reject);
    r.write(body);
    r.end();
  });
}

// Wrapper com retry automático em caso de 429 (rate limit)
// Tenta até 3 vezes com espera exponencial: 2s → 6s → 18s
async function gemini(prompt, apiKey, maxTokens = 500) {
  const MAX_RETRIES = 3;
  let delay = 2000;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      return await _geminiRequest(prompt, apiKey, maxTokens);
    } catch (e) {
      if (e.is429 && attempt < MAX_RETRIES) {
        console.warn(`[Gemini] 429 — aguardando ${delay/1000}s antes da tentativa ${attempt+1}/${MAX_RETRIES}`);
        await new Promise(res => setTimeout(res, delay));
        delay *= 3; // backoff exponencial
        continue;
      }
      throw e; // outros erros ou última tentativa: propaga
    }
  }
}

// ─── HTTP: GERAR CUSTOM TOKEN ────────────────────────────────────────────
// Permite que usuários autenticados localmente (fallback ad-blocker)
// obtenham um Firebase Auth token real com suas claims de role.
// SEGURANÇA: valida credenciais contra o Firestore antes de emitir o token.

exports.gerarCustomToken = onRequest(
  { region: REGION, cors: true },  // aceita qualquer origem — protegido pela validação do Firestore
  async (req, res) => {
    if (req.method !== 'POST') return res.status(405).send('Method Not Allowed');

    const { uid, email, role } = req.body || {};
    if (!uid || !email) return res.status(400).json({ error: 'uid e email obrigatórios' });

    // Valida que o usuário existe no Firestore /users
    try {
      const userDoc = await db.collection('users').doc(uid).get();
      if (!userDoc.exists) {
        // Tenta buscar por email
        const byEmail = await db.collection('users').where('email', '==', email).limit(1).get();
        if (byEmail.empty) {
          return res.status(403).json({ error: 'Usuário não encontrado' });
        }
      }

      // Roles válidas — nunca confia no role enviado pelo cliente
      const VALID_ROLES = ['admin', 'gestor', 'tecnico', 'mdm_admin', 'viewer'];
      const userData = userDoc.exists ? userDoc.data() : {};
      const roleVerificado = VALID_ROLES.includes(userData.role) ? userData.role
        : VALID_ROLES.includes(role) ? role : 'viewer';

      // Gera Custom Token com claims de role
      const admin = require('firebase-admin');
      const token = await admin.auth().createCustomToken(uid, {
        role:  roleVerificado,
        email: email,
      });

      console.log(`[CustomToken] Emitido para ${email} (${roleVerificado})`);
      return res.json({ token, role: roleVerificado });

    } catch (e) {
      console.error('[CustomToken] Erro:', e.message);
      return res.status(500).json({ error: 'Erro interno' });
    }
  }
);

exports.triageChamado = onCall(
  { enforceAppCheck: false, region: REGION, secrets: [GEMINI_KEY] },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { titulo, descricao, area, tipo, categoria } = req.data || {};
    const apiKey = GEMINI_KEY.value();
    if (!apiKey) throw new HttpsError('internal', 'Chave Gemini não configurada');

    const prompt = `Você é analista de suporte de TI da CESAN. Analise o chamado e responda APENAS com JSON puro (sem markdown).\n\nREGRAS DE TIPO:\n- requisicao: usuário PEDE algo (solicito, preciso, quero, instalar, agendar, backup preventivo/segurança/rotina)\n- incidente: algo PAROU (não funciona, erro, falha, parou, quebrou)\n- Backup com segurança/preventivo/rotina = requisicao; backup com falhou/erro = incidente\n\nChamado:
Chamado:
- Título: ${san(titulo,200)}
- Descrição: ${san(descricao,500)}
- Área: ${san(area,100)}
- Tipo: ${san(tipo,50)} | Categoria: ${san(categoria,50)}

JSON:
{"tipo":"requisicao|incidente|problema|mudanca","prioridade":"urgente|muito-alta|alta|media|baixa","categoria":"...","subcategoria":"...","resumo":"1 linha","instrucoes":"para o técnico","confianca":85}`;

    try {
      const r    = await gemini(prompt, apiKey, 400);
      const text = r?.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
      return JSON.parse(text.replace(/```json|```/g,'').trim());
    } catch (e) {
      console.error('[triageChamado] Gemini error:', e.message || e);
      if (e.is429 || (e.message && e.message.includes('429'))) {
        console.warn('[triageChamado] Cota Gemini atingida; retornando fallback local.');
      }
      return { prioridade: 'media', resumo: 'Triagem automática indisponível' };
    }
  }
);

// ─── CALLABLE: INSIGHTS IA ────────────────────────────────────────

exports.getInsightsIA = onCall(
  { enforceAppCheck: false, region: REGION, secrets: [GEMINI_KEY] },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { contexto } = req.data || {};
    const apiKey = GEMINI_KEY.value();
    if (!apiKey) throw new HttpsError('internal', 'Chave Gemini não configurada');

    let totA = 0, totC = 0, abC = 0;
    try {
      const [a,c,ca] = await Promise.all([
        db.collection('ativos').count().get(),
        db.collection('chamados').count().get(),
        db.collection('chamados').where('status','in',['aberto','em-atendimento']).count().get(),
      ]);
      totA = a.data().count; totC = c.data().count; abC = ca.data().count;
    } catch {}

    const prompt = `Você é analista sênior de TI da CESAN (saneamento). Dados:
- Ativos: ${totA} | Chamados: ${totC} | Abertos: ${abC}
- Contexto: ${san(contexto||'N/A',300)}

3 insights estratégicos em JSON puro:
[{"titulo":"...","desc":"2 linhas","acao":"ação recomendada","impacto":"alto|medio|baixo"},...]`;

    try {
      const r    = await gemini(prompt, apiKey, 600);
      const text = r?.candidates?.[0]?.content?.parts?.[0]?.text || '[]';
      return { insights: JSON.parse(text.replace(/```json|```/g,'').trim()) };
    } catch (e) {
      console.error('[getInsightsIA] Gemini error:', e.message || e);
      if (e.is429 || (e.message && e.message.includes('429'))) {
        console.warn('[getInsightsIA] Cota Gemini atingida; retornando fallback vazio.');
      }
      return { insights: [] };
    }
  }
);

// ─── CALLABLE: ANALISAR ATIVO COM GEMINI ─────────────────────────

exports.analisarAtivo = onCall(
  { enforceAppCheck: false, region: REGION, secrets: [GEMINI_KEY] },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { pat, desc, tipo, area, resp, status, ip, hostname, lastSeen, uptimeH, latencyMs } = req.data || {};
    const apiKey = GEMINI_KEY.value();
    if (!apiKey) throw new HttpsError('internal', 'Chave Gemini não configurada');

    let chamadosTexto = '';
    try {
      const cs = await db.collection('chamados').where('pat','==', String(pat||'').slice(0,100)).orderBy('createdAt','desc').limit(5).get();
      if (!cs.empty) chamadosTexto = cs.docs.map(d => `- ${san(d.data().tipo)}: ${san(d.data().desc)} (${san(d.data().status)})`).join('\n');
    } catch {}

    const prompt = `Analiste de TI da CESAN. Analise este ativo em português:
PAT: ${san(pat||ip||'',100)} | Tipo: ${san(tipo,50)} | Área: ${san(area,50)} | Status: ${san(status,30)}
Desc: ${san(desc||hostname||'',150)} | IP: ${san(ip,30)} | Resp: ${san(resp||'—',80)}
Último contato: ${san(lastSeen,30)} | Uptime: ${uptimeH?san(String(uptimeH),20)+'h':'N/A'} | Latência: ${latencyMs?san(String(latencyMs),10)+'ms':'N/A'}
${chamadosTexto ? '\nChamados recentes:\n'+chamadosTexto : ''}

Forneça:
1. Status geral (1 linha)
2. Pontos de atenção (até 3)
3. Recomendações (até 3)
4. Prioridade: Baixa / Média / Alta / Crítica`;

    let text;
    try {
      const r = await gemini(prompt, apiKey, 800);
      text = r?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!text) throw new Error('Vazio');
    } catch (e) {
      // 429 = cota da API Gemini esgotada — mensagem amigável para o usuário
      if (e.is429 || (e.message && e.message.includes('429'))) {
        throw new HttpsError('resource-exhausted',
          'A IA está sobrecarregada no momento (cota Gemini atingida). Tente novamente em alguns minutos.');
      }
      console.error('[analisarAtivo] Gemini error:', e.message || e);
      throw new HttpsError('internal', 'Erro Gemini: ' + (e.message || 'desconhecido'));
    }

    try { await db.collection('ai_logs').add({ tipo:'analise_ativo', pat: String(pat||ip||'').slice(0,100), resultado: text.slice(0,2000), criadoEm: FieldValue.serverTimestamp(), uid: req.auth.uid }); } catch {}

    return { analise: text, pat: pat||ip, geradoEm: new Date().toISOString() };
  }
);

// ─── FIRESTORE TRIGGER: mudança de monitor conectado ─────────────
// Dispara quando o SysackClient atualiza monitoresConectados no ativo.
// Compara seriais com valor anterior — alerta se monitor mudou de PC.

exports.onMonitorConectadoMudou = onDocumentUpdated(
  { document: 'ativos/{ativoId}', region: REGION },
  async event => {
    const antes  = event.data.before.data();
    const depois = event.data.after.data();

    const monitAntes  = JSON.parse(antes?.monitoresConectados  || '[]');
    const monitDepois = JSON.parse(depois?.monitoresConectados || '[]');

    // Nada mudou
    const serialsAntes  = new Set(monitAntes.map(m => m.serial).filter(Boolean));
    const serialsDepois = new Set(monitDepois.map(m => m.serial).filter(Boolean));

    const novos    = [...serialsDepois].filter(s => !serialsAntes.has(s));
    const removidos = [...serialsAntes].filter(s => !serialsDepois.has(s));

    if (!novos.length && !removidos.length) return;

    const pat  = san(depois.pat  || event.params.ativoId);
    const host = san(depois.hostname || depois.ip || '—');
    const area = san(depois.area || '—');

    console.log(`[onMonitor] ${pat}: +${novos.length} -${removidos.length}`);

    // Grava histórico imutável no ativo
    for (const serial of novos) {
      const m = monitDepois.find(x => x.serial === serial);
      await db.collection('ativos').doc(event.params.ativoId)
        .collection('historico').add({
          tipo:   'alerta',
          dot:    'blue',
          titulo: 'Monitor conectado detectado',
          desc:   `${san(m?.fabricante||'')} ${san(m?.modelo||'')} · Serial: ${san(serial)} conectado em ${pat} (${host})`,
          autor:  'SYSACK Event Engine',
          data:   FieldValue.serverTimestamp(),
        });
    }
    for (const serial of removidos) {
      const m = monitAntes.find(x => x.serial === serial);
      await db.collection('ativos').doc(event.params.ativoId)
        .collection('historico').add({
          tipo:   'alerta',
          dot:    'orange',
          titulo: 'Monitor desconectado',
          desc:   `${san(m?.fabricante||'')} ${san(m?.modelo||'')} · Serial: ${san(serial)} desconectado de ${pat} (${host})`,
          autor:  'SYSACK Event Engine',
          data:   FieldValue.serverTimestamp(),
        });
    }

    // Grava em eventos_detectados para o dashboard
    if (novos.length || removidos.length) {
      await db.collection('eventos_detectados').add({
        tipo:           'monitor',
        titulo:         `Monitor ${novos.length ? 'conectado' : 'desconectado'} em ${pat}`,
        desc:           `${novos.map(s => { const m = monitDepois.find(x=>x.serial===s); return `+${san(m?.modelo||s)}`; }).join(', ')} ${removidos.map(s => { const m = monitAntes.find(x=>x.serial===s); return `-${san(m?.modelo||s)}`; }).join(', ')}`.trim(),
        pat, area, ativoId: event.params.ativoId,
        monitoresNovos:    novos,
        monitoresRemovidos: removidos,
        detecEm: FieldValue.serverTimestamp(),
      });
    }

    // Verifica se algum serial recém conectado estava em outro PC antes
    // Busca no histórico global de monitores
    for (const serial of novos) {
      const snap = await db.collection('monitor_historico')
        .where('serial', '==', serial)
        .orderBy('data', 'desc')
        .limit(1).get();

      if (!snap.empty) {
        const ultimo = snap.docs[0].data();
        // Se estava em outro ativo antes, alerta de movimentação
        if (ultimo.ativoId && ultimo.ativoId !== event.params.ativoId) {
          const emails = await getGestorEmails();
          const m = monitDepois.find(x => x.serial === serial);
          const corpo = `
            <p>O Event Engine detectou uma <strong>movimentação de monitor</strong> não registrada.</p>
            <table>
              <tr><th>Monitor</th><td><strong>${esc(m?.fabricante||'')} ${esc(m?.modelo||'—')}</strong></td></tr>
              <tr><th>Serial</th><td style="font-family:monospace">${esc(serial)}</td></tr>
              <tr><th>Estava em</th><td style="color:#D97706">${esc(ultimo.pat||ultimo.ativoId)}</td></tr>
              <tr><th>Agora em</th><td style="color:#059669;font-weight:700">${esc(pat)} (${esc(host)})</td></tr>
              <tr><th>Área</th><td>${esc(area)}</td></tr>
            </table>
            <p>Se esta movimentação não foi registrada no sistema, verifique se há chamado de movimentação em aberto.</p>
            <a href="https://sysack.vercel.app/#ativos" class="btn">Ver no SYSACK</a>`;

          if (emails.length) {
            await sendEmail(
              emails.join(','),
              `[SYSACK] 🖥️ Monitor movido sem registro — Serial: ${san(serial)}`,
              emailHtml('Event Engine — Monitor movimentado', corpo, '#D97706')
            );
          }
        }
      }

      // Atualiza histórico global do monitor
      await db.collection('monitor_historico').add({
        serial,
        fabricante: san(monitDepois.find(x=>x.serial===serial)?.fabricante||''),
        modelo:     san(monitDepois.find(x=>x.serial===serial)?.modelo||''),
        ativoId:    event.params.ativoId,
        pat,
        host,
        area,
        data:       FieldValue.serverTimestamp(),
      });
    }
  }
);

// ─── CALLABLE: histórico de movimentações de um monitor ──────────
exports.getHistoricoMonitor = onCall(
  { enforceAppCheck: false, region: REGION },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');
    const { serial } = req.data || {};
    if (!serial) throw new HttpsError('invalid-argument', 'serial obrigatório');

    const snap = await db.collection('monitor_historico')
      .where('serial', '==', san(serial))
      .orderBy('data', 'desc')
      .limit(50).get();

    return {
      historico: snap.docs.map(d => {
        const h = d.data();
        return {
          ativoId: h.ativoId || '',
          pat:     h.pat     || '—',
          host:    h.host    || '—',
          area:    h.area    || '—',
          data:    h.data?.toDate?.()?.toISOString() || '',
        };
      }),
    };
  }
);



// ─── FIRESTORE TRIGGER: rastreabilidade total do ativo ─────────────
// Registra no histórico alterações em grupo, área, card/status, responsável,
// localização, monitor e IP. Se mudar de faixa de IP, gera alerta crítico.
function faixaIP_SYSACK(ip) {
  const m = String(ip || '').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return '';
  return `${m[1]}.${m[2]}.${m[3]}.0/24`;
}
function valor_SYSACK(v) {
  if (v === undefined || v === null || v === '') return '—';
  if (Array.isArray(v)) return v.map(x => typeof x === 'object' ? (x.nome || x.caption || x.pat || x.desc || JSON.stringify(x)) : x).join(', ') || '—';
  if (typeof v === 'object') return v.nome || v.caption || v.pat || v.desc || JSON.stringify(v);
  return String(v);
}
const CAMPOS_RASTREADOS_SYSACK = [
  ['grupo','Grupo'], ['area','Área'], ['setor','Setor'], ['card','Card'], ['coluna','Card'],
  ['status','Status'], ['resp','Responsável'], ['responsavel','Responsável'], ['matriculaResp','Matrícula responsável'],
  ['loc','Localização'], ['local','Localização'], ['sala','Sala'], ['hostname','Hostname'],
  ['ip','IP'], ['pat','Patrimônio'], ['monitor','Monitor'], ['monitorId','Monitor'], ['monitores','Monitores']
];
exports.rastrearAlteracoesAtivo = onDocumentUpdated(
  { document: 'ativos/{ativoId}', region: REGION },
  async event => {
    const antes  = event.data.before.data() || {};
    const depois = event.data.after.data()  || {};
    const ativoId = event.params.ativoId;
    const pat = san(depois.pat || antes.pat || ativoId, 80);
    const batch = [];

    for (const [campo,label] of CAMPOS_RASTREADOS_SYSACK) {
      const a = valor_SYSACK(antes[campo]);
      const d = valor_SYSACK(depois[campo]);
      if (a === d) continue;
      let tipo = 'alteracao_cadastro', dot = 'blue', titulo = `${label} alterado`, alerta = false;
      if (['area','setor','loc','local','sala'].includes(campo)) { tipo = 'movimentacao_area_local'; titulo = `${label} do ativo alterado`; }
      if (['grupo','card','coluna','status'].includes(campo)) { tipo = 'movimentacao_fluxo'; titulo = `${label} / fluxo alterado`; }
      if (['resp','responsavel','matriculaResp'].includes(campo)) { tipo = 'troca_responsavel'; titulo = 'Responsável do ativo alterado'; }
      if (['monitor','monitorId','monitores'].includes(campo)) { tipo = 'troca_monitor'; titulo = 'Monitor vinculado ao ativo alterado'; dot = 'orange'; alerta = true; }
      if (campo === 'pat') { tipo = 'alteracao_patrimonio'; dot = 'red'; alerta = true; }
      if (campo === 'ip') { tipo = 'alteracao_ip'; titulo = 'IP do ativo alterado'; dot = 'orange'; }
      const desc = `${label}: ${a} → ${d}`;
      batch.push(db.collection('ativos').doc(ativoId).collection('historico').add({
        tipo, evento: tipo, dot, titulo, label: titulo, desc, campo, de: a, para: d,
        autor: 'SYSACK Event Engine', data: FieldValue.serverTimestamp(), syncSource: 'firestore-trigger',
      }));
      if (alerta) batch.push(db.collection('alertas').add({
        tipo, titulo, desc, severidade: campo === 'pat' ? 'critical' : 'warning',
        ativoId, pat, ip: depois.ip || antes.ip || '', lida: false,
        createdAt: FieldValue.serverTimestamp(), origem: 'firestore-trigger', campo, de: a, para: d,
      }));
    }

    const faixaAntes = faixaIP_SYSACK(antes.ip);
    const faixaDepois = faixaIP_SYSACK(depois.ip);
    if (faixaAntes && faixaDepois && faixaAntes !== faixaDepois) {
      const desc = `Faixa de IP alterada: ${faixaAntes} → ${faixaDepois} · IP: ${valor_SYSACK(antes.ip)} → ${valor_SYSACK(depois.ip)}`;
      batch.push(db.collection('ativos').doc(ativoId).collection('historico').add({
        tipo: 'mudanca_faixa_ip', evento: 'mudanca_faixa_ip', dot: 'red',
        titulo: 'Máquina mudou de faixa de IP', label: 'Máquina mudou de faixa de IP', desc,
        ipAnterior: antes.ip || '', ipNovo: depois.ip || '', faixaAnterior: faixaAntes, faixaNova: faixaDepois,
        autor: 'SYSACK Event Engine', data: FieldValue.serverTimestamp(), syncSource: 'firestore-trigger',
      }));
      batch.push(db.collection('alertas').add({
        tipo: 'mudanca_faixa_ip', titulo: 'Máquina mudou de faixa de IP', desc,
        severidade: 'critical', ativoId, pat, ip: depois.ip || '', ipAnterior: antes.ip || '', ipNovo: depois.ip || '',
        faixaAnterior: faixaAntes, faixaNova: faixaDepois, lida: false,
        createdAt: FieldValue.serverTimestamp(), origem: 'firestore-trigger',
      }));
      batch.push(db.collection('eventos_detectados').add({
        tipo: 'mudanca_faixa_ip', titulo: 'Máquina mudou de faixa de IP', desc,
        ativoId, pat, ip: depois.ip || '', faixaAnterior: faixaAntes, faixaNova: faixaDepois,
        detecEm: FieldValue.serverTimestamp(), origem: 'firestore-trigger',
      }));
    }
    if (batch.length) await Promise.allSettled(batch);
  }
);

async function ativosDoChamado_SYSACK(ch) {
  const refs = new Map();
  async function addByPat(pat) {
    if (!pat) return;
    const snap = await db.collection('ativos').where('pat','==',String(pat)).limit(1).get();
    snap.forEach(d => refs.set(d.id, { id: d.id, ...d.data() }));
  }
  await addByPat(ch.pat);
  for (const av of (ch.ativosVinculados || [])) {
    if (av.id || av.docId) {
      const id = av.id || av.docId;
      const doc = await db.collection('ativos').doc(id).get();
      if (doc.exists) refs.set(doc.id, { id: doc.id, ...doc.data() });
    }
    await addByPat(av.pat);
  }
  if (ch.movimentacao) {
    await addByPat(ch.movimentacao.patAntigo);
    await addByPat(ch.movimentacao.patNovo);
  }
  return [...refs.values()];
}
async function registrarChamadoNoHistoricoAtivo_SYSACK(ch, chamadoId, acao) {
  const ativos = await ativosDoChamado_SYSACK(ch);
  if (!ativos.length) return;
  const status = ch.status || 'aberto';
  const tipo = acao === 'criado' ? 'chamado_aberto' : ['fechado','concluido'].includes(status) ? 'chamado_encerrado' : 'chamado_atualizado';
  const titulo = tipo === 'chamado_aberto' ? 'Chamado aberto para o ativo' : tipo === 'chamado_encerrado' ? 'Chamado encerrado para o ativo' : 'Chamado atualizado para o ativo';
  await Promise.allSettled(ativos.map(a => db.collection('ativos').doc(a.id).collection('historico').add({
    tipo, evento: 'chamado', dot: tipo === 'chamado_encerrado' ? 'green' : 'blue', titulo, label: titulo,
    chamadoId, statusChamado: status,
    desc: `Chamado ${chamadoId} · ${status} · ${san(ch.titulo || ch.desc || '', 180)}`,
    autor: 'SYSACK Event Engine', data: FieldValue.serverTimestamp(), syncSource: 'firestore-trigger',
  })));
}
exports.rastrearChamadoCriadoNoAtivo = onDocumentCreated(
  { document: 'chamados/{chamadoId}', region: REGION },
  async event => registrarChamadoNoHistoricoAtivo_SYSACK(event.data.data() || {}, event.params.chamadoId, 'criado')
);
exports.rastrearChamadoAtualizadoNoAtivo = onDocumentUpdated(
  { document: 'chamados/{chamadoId}', region: REGION },
  async event => registrarChamadoNoHistoricoAtivo_SYSACK(event.data.after.data() || {}, event.params.chamadoId, 'atualizado')
);

// ─── CALLABLE: extrair PAT da foto da plaqueta (Gemini Vision) ───
// Recebe imagem base64, usa IA para ler o número de patrimônio
// impresso/colado na plaqueta do monitor.

exports.extrairPATdaFoto = onCall(
  { enforceAppCheck: false, region: REGION },
  async req => {
    if (!req.auth) throw new HttpsError('unauthenticated', 'Login necessário');

    const { imageBase64 } = req.data || {};
    if (!imageBase64) throw new HttpsError('invalid-argument', 'imageBase64 obrigatório');

    // Usa Gemini Vision para extrair o PAT da plaqueta
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      // Fallback sem IA: retorna null para o frontend pedir digitação manual
      return { pat: null, confianca: 0, metodo: 'manual' };
    }

    try {
      const body = JSON.stringify({
        contents: [{
          parts: [
            {
              text: 'Esta é uma foto de uma plaqueta de patrimônio de equipamento de TI. ' +
                    'Extraia SOMENTE o número de patrimônio (PAT) que aparece na plaqueta. ' +
                    'O número geralmente é um código numérico de 4-6 dígitos. ' +
                    'Responda APENAS com o número, sem texto adicional. ' +
                    'Se não conseguir identificar, responda com "NAO_ENCONTRADO".'
            },
            {
              inline_data: {
                mime_type: 'image/jpeg',
                data: imageBase64,
              }
            }
          ]
        }],
        generationConfig: { maxOutputTokens: 50, temperature: 0 },
      });

      const resultado = await new Promise((resolve, reject) => {
        const r = require('https').request({
          hostname: 'generativelanguage.googleapis.com',
          path: `/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`,
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
        }, res => {
          let raw = '';
          res.on('data', c => raw += c);
          res.on('end', () => { try { resolve(JSON.parse(raw)); } catch(e) { reject(e); } });
        });
        r.on('error', reject);
        r.write(body);
        r.end();
      });

      const texto = resultado?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
      if (!texto || texto === 'NAO_ENCONTRADO' || texto.length > 20) {
        return { pat: null, confianca: 0, metodo: 'gemini' };
      }

      // Limpa o texto: mantém só dígitos e hífens
      const patLimpo = texto.replace(/[^0-9\-]/g, '').replace(/^-+|-+$/g, '');
      if (patLimpo.length < 2) return { pat: null, confianca: 0, metodo: 'gemini' };

      return { pat: patLimpo, confianca: 0.9, metodo: 'gemini' };
    } catch(e) {
      console.error('[extrairPATdaFoto]', e.message);
      return { pat: null, confianca: 0, metodo: 'erro' };
    }
  }
);
