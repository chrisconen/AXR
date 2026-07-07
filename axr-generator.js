// ═══════════════════════════════════════════════════════════════════════════════
// AXR Receipt Generator - N8N Code node logika v0.2
// ═══════════════════════════════════════════════════════════════════════════════
// Ez a fuggveny azt csinalja, amit az N8N Code node fog: a workflow vegen
// osszegyujti a releváns node-ok kimeneteit, es legyartja a teljes receipt-lancot.
// Az N8N-ben a $('Node Name').all() hivja vissza a node kimeneteket; itt ezt
// egy 'ctx' objektum szimulalja, hogy tesztelheto legyen a sandboxban.
//
// 0.2 valtozas (spec 7.1): az input_hash mostantol minden lepesnel a lepes
// TENYLEGES inputjabol szamol. Ezt minden tanusitando node a kimenetebe tett
// __axr_input markerbol kapjuk meg (axr-core: splitAxrInput). A generator igy
// nem feltetelez lineáris graph-ot es nem fugg a node-ok kozti elek sorrendjetol.
// ═══════════════════════════════════════════════════════════════════════════════

const axr = require('./axr-core');

// A hat tanusitando node, fix sorrendben. Amelyik nem futott le, az kimarad.
const STEP_NODES = [
  { node: 'Normalize Payload - HU', type: 'n8n-nodes-base.code',          deterministic: true, logic_version: '3.2 HU' },
  { node: 'Check Day Schedule',     type: 'n8n-nodes-base.googleCalendar', deterministic: true, logic_version: null     },
  { node: 'The Brain (Logic)',      type: 'n8n-nodes-base.code',          deterministic: true, logic_version: '5.0 HU' },
  { node: 'Fresh Calendar Check',   type: 'n8n-nodes-base.googleCalendar', deterministic: true, logic_version: null     },
  { node: 'Slot Still Free?',       type: 'n8n-nodes-base.code',          deterministic: true, logic_version: null     },
  { node: 'Create Booking',         type: 'n8n-nodes-base.googleCalendar', deterministic: true, logic_version: null     }
];

// A Brain kimenetebol kiemeli a strukturalt dontest a receipt szamara.
function extractBrainDecision(brainOutput) {
  const o = brainOutput;
  return {
    status: o.status || o.error || 'UNKNOWN',
    available: o.available === true,
    cluster_id: o.cluster?.id || o.details?.requestedZone || null,
    cluster_country: o.cluster?.country || null,
    assigned_slot: o.slot ? `${o.slot.startTime}-${o.slot.endTime}` : null,
    travel_buffer_applied: o.calendar?.travelBufferApplied || null,
    reason: o.status === 'ANCHOR_BOOKING' ? 'empty_day_anchor'
          : o.status === 'SLOT_ADJUSTED' ? 'conflict_shifted'
          : o.status === 'SLOT_AVAILABLE' ? 'slot_free'
          : o.error === 'ZONE_INCOMPATIBLE' ? (o.details?.reason || 'distance_too_far')
          : o.error === 'DAY_FULL' ? 'exceeds_work_end'
          : 'unknown'
  };
}

// Egy node kimenetebol epit nem-PII input_summary-t.
function buildInputSummary(nodeName, nodeOutput, normalizedBody) {
  if (nodeName === 'Normalize Payload - HU') {
    const b = normalizedBody;
    return {
      date: b.date, duration_minutes: b.totalDuration,
      requested_slot_start: b.slotStartTime,
      city: b.locationData?.city || null, has_items: b.validation?.hasItems ?? null
    };
  }
  if (nodeName === 'Check Day Schedule' || nodeName === 'Fresh Calendar Check') {
    const events = Array.isArray(nodeOutput) ? nodeOutput.filter(e => e && e.id) : [];
    return { existing_events_count: events.length, date: normalizedBody.date };
  }
  if (nodeName === 'The Brain (Logic)') {
    const b = normalizedBody;
    return {
      date: b.date, duration_minutes: b.totalDuration,
      requested_slot_start: b.slotStartTime
    };
  }
  if (nodeName === 'Slot Still Free?') {
    return { date: normalizedBody.date };
  }
  if (nodeName === 'Create Booking') {
    return { date: normalizedBody.date };
  }
  return {};
}

// ── Fo generator ───────────────────────────────────────────────────────────────
// ctx.get(nodeName)        -> a node kimenete, vagy null ha nem futott
// ctx.normalizedBody       -> a Normalize Payload .body kimenete
// ctx.rawWebhookBody       -> a nyers webhook body (PII)
// ctx.brainOutput          -> a Brain kimenete
// ctx.prevWorkflowHash     -> az elozo workflow receipt hash-e ezen az agenten
// ctx.privateKeyPem        -> az alairo kulcs
function generateReceipts(ctx) {
  const workflowReceiptId = axr.uuid();
  const triggerTs = ctx.triggerTimestamp || new Date().toISOString();

  const actor = {
    agent_id: 'eco-clean-booking-hu',
    agent_type: 'n8n-workflow',
    operator: 'Conen Digital',
    on_behalf_of: 'ECO Clean HU'
  };

  // Figyelmeztetesek gyujtese: ha egy node nem hagyott __axr_input markert,
  // az input_hash null lesz - nem hazudunk uniform hash-t. A hivo (n8n-node)
  // ezt naplozhatja.
  const warnings = [];

  // 1. Lepes-receiptek epitese, csak a tenylegesen lefutott node-okra
  const stepReceipts = [];
  let prevStepHash = null;
  let sequence = 0;

  for (const def of STEP_NODES) {
    const rawOutput = ctx.get(def.node);
    if (rawOutput === null || rawOutput === undefined) continue; // nem futott le -> kimarad

    sequence += 1;

    // 0.2: a node kimenetebol levalasztjuk a __axr_input markert.
    //  - stepInput  : a node TENYLEGES bemenete -> ebbol szamol az input_hash
    //  - cleanOutput: a kimenet a marker NELKUL -> ebbol szamol az output_hash
    const { input: stepInput, output: cleanOutput } = axr.splitAxrInput(rawOutput);

    let inputHash;
    if (stepInput === undefined) {
      // a node nem hagyott markert - nem talalunk ki hamis hash-t
      inputHash = null;
      warnings.push(`${def.node}: nincs __axr_input marker a kimeneten - input_hash null`);
    } else {
      inputHash = axr.sha256(stepInput);
    }

    const inputSummary = buildInputSummary(def.node, cleanOutput, ctx.normalizedBody);

    const stepBody = {
      axr_version: axr.AXR_VERSION,
      receipt_type: 'step',
      receipt_id: axr.uuid(),
      workflow_receipt_id: workflowReceiptId,
      sequence: sequence,
      timestamp: ctx.stepTimestamp ? ctx.stepTimestamp(def.node) : triggerTs,
      step: {
        node_name: def.node,
        node_type: def.type,
        logic_version: def.logic_version,
        model: null,
        deterministic: def.deterministic
      },
      io: {
        input_hash: inputHash,
        output_hash: axr.sha256(cleanOutput),
        input_summary: inputSummary,
        decision: def.node === 'The Brain (Logic)'
          ? extractBrainDecision(ctx.brainOutput)
          : null
      },
      approval: null,
      previous_receipt_hash: prevStepHash
    };

    const signature = axr.signReceipt(stepBody, ctx.privateKeyPem);
    const stepReceipt = { ...stepBody, signature };
    prevStepHash = axr.sha256(stepReceipt);
    stepReceipts.push(stepReceipt);
  }

  // 2. Workflow-szintu receipt
  const brain = extractBrainDecision(ctx.brainOutput);
  const finalStatus = ctx.finalStatusOverride || brain.status;

  const workflowBody = {
    axr_version: axr.AXR_VERSION,
    receipt_type: 'workflow',
    receipt_id: workflowReceiptId,
    workflow: {
      workflow_id: 'eco-clean-geo-cluster-booking-hu',
      workflow_version: '5.0',
      webhook_path: 'booking-request-hu',
      trigger_timestamp: triggerTs,
      completion_timestamp: ctx.completionTimestamp || new Date().toISOString()
    },
    actor: actor,
    request: {
      input_hash: axr.sha256(ctx.rawWebhookBody),
      customer_ref: axr.customerRef(
        ctx.rawWebhookBody.name, ctx.rawWebhookBody.email, ctx.rawWebhookBody.phone
      )
    },
    outcome: {
      final_status: finalStatus,
      available: brain.available && finalStatus === brain.status,
      decision_summary: buildDecisionSummary(brain, finalStatus)
    },
    step_chain: stepReceipts.map(r => r.receipt_id),
    chain_root_hash: prevStepHash,
    approval: null,
    previous_receipt_hash: ctx.prevWorkflowHash || null
  };

  const workflowSignature = axr.signReceipt(workflowBody, ctx.privateKeyPem);
  const workflowReceipt = { ...workflowBody, signature: workflowSignature };
  const workflowReceiptHash = axr.sha256(workflowReceipt);

  return { workflowReceipt, workflowReceiptHash, stepReceipts, warnings };
}

function buildDecisionSummary(brain, finalStatus) {
  if (finalStatus === 'SLOT_TAKEN_ON_RECHECK') {
    return `Brain javasolt slotot (${brain.assigned_slot}), de a friss ellenorzes konfliktust talalt - foglalas elmaradt`;
  }
  if (brain.available) {
    return `Zone ${brain.cluster_id}, slot ${brain.assigned_slot}, status ${brain.status}`;
  }
  return `Elutasitva: ${brain.status}, ok: ${brain.reason}, zona: ${brain.cluster_id || 'ismeretlen'}`;
}

// ── Error-path receipt (P2) ─────────────────────────────────────────────────
// Egy BUKOTT futas (node throw / workflow error-out) is kapjon ALAIRT, LANCOLT
// receiptet. Ma a generator csak a happy path-ot es az explicit elutasitasokat
// (final_status) fedi; a kemeny hiba a try/catch-ben egy __axr.error
// passthrough-ra esik, signed receipt nelkul - pedig vitathatoan a bukott futas
// a legfontosabb, amirol bizonyitek kell (forras: nguyenthieutoan, n8n forum).
//
// SCOPE: ez a generator LEFEDETTSEGET bovit, NEM a wire formatot. Ez egy normal
// 'workflow' receipt, aminek a final_status-a WORKFLOW_ERROR (kulon, egyertelmu
// hiba-allapot), plusz egy ADDITIV 'error' bizonyitek-blokk - ugyanugy additiv,
// ahogy a 0.3 'generation' vagy a 0.4 'side_effects' volt. A verifier (1-6/15.
// ellenorzes) valtozatlanul elfogadja: nincs uj ellenorzes, nincs uj exit-kod,
// a regi logok byte-azonosan verifikalnak. A frozen 1.x kontraktus erintetlen.
//
// ADATVEDELEM: a hibauzenet PII-t / ugyfel-inputot tartalmazhat (lasd Bug C, ahol
// a rejection a customer sajat uzenetet visszhangozta), ezert CSAK a sha256
// ujjlenyomatat (message_hash) tanusitjuk - a cleartext SOSEM kerul a logba.
//
// ctx:
//   error: { failed_node?, error_class?, message?, execution_id?, occurred_at? }
//   privateKeyPem        -> az alairo kulcs (kotelezo)
//   rawWebhookBody?      -> ha elerheto: request.input_hash + customer_ref ebbol
//   prevWorkflowHash?    -> az elozo workflow receipt chainHash-e ezen az agenten
//   workflow?, actor?    -> metaadat-felulirasok (default: a pilot ertekei)
//   axrVersion?          -> default a pilot 0.2 (igy a meglevo lanccal folytatodik)
//   stepReceipts?        -> opcionalis, MAR alairt+lancolt reszleges lepesek
//   chainRootHash?       -> ha vannak stepReceipts: az utolso chainHash-e
//   triggerTimestamp?, completionTimestamp?
function generateErrorReceipt(ctx) {
  if (!ctx || !ctx.privateKeyPem) {
    throw new Error('generateErrorReceipt: privateKeyPem kotelezo');
  }
  const V = ctx.axrVersion || axr.AXR_VERSION;
  const workflowReceiptId = axr.uuid();
  const triggerTs = ctx.triggerTimestamp || new Date().toISOString();
  const err = ctx.error || {};

  const errorBlock = {
    failed_node: err.failed_node || null,
    error_class: err.error_class || null,
    // PII-vedelem: csak az ujjlenyomat, sosem a cleartext uzenet
    message_hash: (err.message !== undefined && err.message !== null)
      ? axr.sha256(String(err.message)) : null,
    execution_id: err.execution_id || null,
    occurred_at: err.occurred_at || triggerTs
  };

  const stepReceipts = Array.isArray(ctx.stepReceipts) ? ctx.stepReceipts : [];

  const workflowBody = {
    axr_version: V,
    receipt_type: 'workflow',
    receipt_id: workflowReceiptId,
    workflow: {
      workflow_id: (ctx.workflow && ctx.workflow.workflow_id) || 'eco-clean-geo-cluster-booking-hu',
      workflow_version: (ctx.workflow && ctx.workflow.workflow_version) || '5.0',
      webhook_path: (ctx.workflow && ctx.workflow.webhook_path) || 'booking-request-hu',
      trigger_timestamp: triggerTs,
      completion_timestamp: ctx.completionTimestamp || new Date().toISOString()
    },
    actor: ctx.actor || {
      agent_id: 'eco-clean-booking-hu',
      agent_type: 'n8n-workflow',
      operator: 'Conen Digital',
      on_behalf_of: 'ECO Clean HU'
    },
    request: {
      input_hash: ctx.rawWebhookBody ? axr.sha256(ctx.rawWebhookBody) : null,
      customer_ref: ctx.rawWebhookBody
        ? axr.customerRef(ctx.rawWebhookBody.name, ctx.rawWebhookBody.email, ctx.rawWebhookBody.phone)
        : null
    },
    outcome: {
      final_status: 'WORKFLOW_ERROR',
      available: false,
      decision_summary: buildErrorSummary(errorBlock)
    },
    error: errorBlock,
    step_chain: stepReceipts.map(r => r.receipt_id),
    // verifier 3. ellenorzes: lepesek nelkul a chain_root_hash null kell legyen
    chain_root_hash: stepReceipts.length ? (ctx.chainRootHash || null) : null,
    approval: null,
    previous_receipt_hash: ctx.prevWorkflowHash || null
  };

  const signature = axr.signReceipt(workflowBody, ctx.privateKeyPem);
  const workflowReceipt = { ...workflowBody, signature };
  const workflowReceiptHash = axr.chainHash(workflowReceipt);

  return { workflowReceipt, workflowReceiptHash, stepReceipts, warnings: [] };
}

// Nem-PII osszefoglalo a hiba-receipthez (a cleartext uzenet sosem kerul bele).
function buildErrorSummary(errorBlock) {
  const node = errorBlock.failed_node || 'ismeretlen node';
  const cls = errorBlock.error_class || 'ismeretlen hiba';
  return `Hibas futas: "${node}" elszallt (${cls}) - a foglalas nem fejezodott be`;
}

module.exports = { generateReceipts, STEP_NODES, generateReceiptsV3, generateErrorReceipt };

// ═══════════════════════════════════════════════════════════════════════════════
// 0.3 generator (Stage C) - marker-vezerelt, generativ lepeseket is kezel
// ═══════════════════════════════════════════════════════════════════════════════
// A 0.2 generator a pilot hat node-jara van huzalozva. A 0.3 generator ezzel
// szemben ALTALANOS: a lepeseket a hivo adja meg (ctx.steps), es minden lepesnel
// a node kimenetebol levalasztott markerek dontik el a tipust:
//   - __axr_gen jelen van  -> GENERATIV lepes (kind: 'generative', generation blokk,
//                             model a markerbol, io.decision = null)
//   - csak __axr_input van -> determinisztikus lepes (mint a 0.2-ben)
//
// Az evidence-graph (spec 3.4): egy lepes def.inputsFrom-ja node-neveket sorol,
// amiket a generator a mar megepitett lepesek receipt_id-jaira old fel, es az
// io melletti 'inputs' tombbe ir. Igy a verifier (9. ellenorzes) checkelni tudja,
// hogy "a Brain ezt a modell-kimenetet kapta".
//
// 0.3 mezok: axr_version '0.3', step.kind, inputs, anchor_ref:null,
// actor.identity_ref. A lancolas a kozos chainHash-sel tortenik (anchor_ref nelkul),
// hogy a kesobbi horgonyzas ne torje el a lancot.
//
// ctx:
//   steps        : [ { node, type, logic_version?, inputsFrom?:[nodeNames],
//                      decision?:bool, extractDecision?:fn, inputSummary?:fn } ]
//   get(nodeName): a node nyers kimenete (markerekkel), vagy null ha nem futott
//   rawWebhookBody, prevWorkflowHash, privateKeyPem
//   workflow {workflow_id, workflow_version, webhook_path}, actor {...}
//   triggerTimestamp?, completionTimestamp?, stepTimestamp?(node)->ts
//   finalStatusOverride?, decisionSummary?
function generateReceiptsV3(ctx) {
  const V = '0.3';
  const workflowReceiptId = axr.uuid();
  const triggerTs = ctx.triggerTimestamp || new Date().toISOString();
  const warnings = [];
  const stepReceipts = [];
  const nodeToReceiptId = {};
  let prevStepHash = null;
  let sequence = 0;
  let decisionForWorkflow = null;

  for (const def of (ctx.steps || [])) {
    const rawOutput = ctx.get(def.node);
    if (rawOutput === null || rawOutput === undefined) continue; // nem futott -> kimarad
    sequence += 1;

    // mindket marker levalasztasa: a tiszta output egyiket se tartalmazza
    const afterInput = axr.splitAxrInput(rawOutput);
    const afterGen = axr.splitAxrGen(afterInput.output);
    const stepInput = afterInput.input;
    const gen = afterGen.gen;
    const cleanOutput = afterGen.output;
    const generative = gen !== undefined;

    let inputHash;
    if (stepInput === undefined) {
      inputHash = null;
      warnings.push(`${def.node}: nincs __axr_input marker - input_hash null`);
    } else {
      inputHash = axr.sha256(stepInput);
    }

    // inputs evidence-graph: node-nevek -> mar megepitett lepesek receipt_id-jai
    const inputs = [];
    for (const src of (def.inputsFrom || [])) {
      if (nodeToReceiptId[src]) inputs.push(nodeToReceiptId[src]);
      else warnings.push(`${def.node}: inputsFrom "${src}" nincs tanusitott (korabbi) lepeskent`);
    }

    let decision = null;
    if (!generative && def.decision) {
      const co = Array.isArray(cleanOutput) ? (cleanOutput[0] || {}) : cleanOutput;
      decision = def.extractDecision ? def.extractDecision(co) : co;
      decisionForWorkflow = decision;
    }

    const stepBody = {
      axr_version: V,
      receipt_type: 'step',
      receipt_id: axr.uuid(),
      workflow_receipt_id: workflowReceiptId,
      sequence: sequence,
      timestamp: ctx.stepTimestamp ? ctx.stepTimestamp(def.node) : triggerTs,
      step: {
        node_name: def.node,
        node_type: def.type,
        logic_version: def.logic_version || null,
        kind: generative ? 'generative' : 'deterministic',
        deterministic: !generative,
        model: generative ? (gen.model || null) : null
      },
      io: {
        input_hash: inputHash,
        output_hash: axr.sha256(cleanOutput),
        input_summary: def.inputSummary ? def.inputSummary(cleanOutput) : {},
        decision: decision
      },
      inputs: inputs,
      approval: null,
      previous_receipt_hash: prevStepHash,
      anchor_ref: null
    };
    if (generative) stepBody.generation = axr.buildGeneration(gen);

    const signature = axr.signReceipt(stepBody, ctx.privateKeyPem);
    const stepReceipt = { ...stepBody, signature };
    prevStepHash = axr.chainHash(stepReceipt);
    nodeToReceiptId[def.node] = stepReceipt.receipt_id;
    stepReceipts.push(stepReceipt);
  }

  const finalStatus = ctx.finalStatusOverride ||
    (decisionForWorkflow && decisionForWorkflow.status) || 'UNKNOWN';

  const workflowBody = {
    axr_version: V,
    receipt_type: 'workflow',
    receipt_id: workflowReceiptId,
    workflow: {
      workflow_id: (ctx.workflow && ctx.workflow.workflow_id) || 'workflow',
      workflow_version: (ctx.workflow && ctx.workflow.workflow_version) || null,
      webhook_path: (ctx.workflow && ctx.workflow.webhook_path) || null,
      trigger_timestamp: triggerTs,
      completion_timestamp: ctx.completionTimestamp || new Date().toISOString()
    },
    actor: {
      agent_id: (ctx.actor && ctx.actor.agent_id) || 'agent',
      agent_type: (ctx.actor && ctx.actor.agent_type) || 'n8n-workflow',
      operator: (ctx.actor && ctx.actor.operator) || null,
      on_behalf_of: (ctx.actor && ctx.actor.on_behalf_of) || null,
      identity_ref: (ctx.actor && ctx.actor.identity_ref) || null
    },
    request: {
      input_hash: axr.sha256(ctx.rawWebhookBody),
      customer_ref: ctx.rawWebhookBody
        ? axr.customerRef(ctx.rawWebhookBody.name, ctx.rawWebhookBody.email, ctx.rawWebhookBody.phone)
        : null
    },
    outcome: {
      final_status: finalStatus,
      available: !!(decisionForWorkflow && decisionForWorkflow.available),
      decision_summary: ctx.decisionSummary || finalStatus
    },
    step_chain: stepReceipts.map(r => r.receipt_id),
    chain_root_hash: prevStepHash,
    approval: null,
    previous_receipt_hash: ctx.prevWorkflowHash || null,
    anchor_ref: null
  };

  const workflowSignature = axr.signReceipt(workflowBody, ctx.privateKeyPem);
  const workflowReceipt = { ...workflowBody, signature: workflowSignature };
  const workflowReceiptHash = axr.chainHash(workflowReceipt);

  return { workflowReceipt, workflowReceiptHash, stepReceipts, warnings };
}
