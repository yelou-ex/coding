package com.fusepir.cape;

import com.fusepir.bloom.*;

import com.fusepir.common.BfGen;

import com.fusepir.fusepir.*;


import com.fusepir.prim.*;
import com.fusepir.bff.*;
import com.fusepir.demo.*;
import com.fusepir.probe.*;
import com.fusepir.nativejni.NativeBlindRotate;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * <b>CAPE native demo service.</b> A long-lived Java process that owns the native
 * context, runs SETUP once at startup, and serves the four-step query over HTTP.
 *
 * <p>Uses only {@code com.sun.net.httpserver} — no framework, no extra jars.
 *
 * <p>What actually crosses into native per query: the flattened plaintext table and
 * three index arrays. The column selectors are built and used inside
 * {@code nativeCapeAnswer}, and the row selector is the LWE index
 * {@code beta_a = sum_i a_i*s_i + rIdx[a]}, also built there. So QUERY sends no
 * ciphertext at all — which is why "QUERY" is cheap here and all the time is ANSWER.
 *
 * <p>⚠️ This is a single-process loopback: the same JVM holds the secret key and runs
 * the query. It demonstrates architecture and timing, not a two-party deployment.
 *
 * <p>Run: {@code .\run-mpc4j.ps1 -Class com.fusepir.demo.CapeDemoService [port] [N] [d] [dbPath]}
 */
public final class CapeDemoService {

    private static final int R = 16;
    private static final int K = 3;
    // t 与 gadget 基位宽【从数据集读】，不再硬编码 —— 这样服务与 keywords.json
    // 不可能不一致。meta.plainModulus 是建库时就写进库里的（build_dataset.py 写了
    // 这个字段却一直没人读）；meta.baseBits 是本次新增的。
    //
    // 为什么默认就是最快的一组（t=2^32, base=2^32 ⇒ levels 6）：
    // 平衡分解的位必须落在 [0, t) 内 ⇒ base < 2t，所以 base 的天花板由 t 决定。
    // t=65537 时 base 只能到 2^16 ⇒ levels=11；t=2^32 时 base 到 2^32 ⇒ levels=6，
    // 一次 CMUX 从 41.4 ms 降到 26.3 ms，ANSWER 176 s -> 102 s。
    // 仍可用 -Dcape.t / -Dcape.b 覆盖（做对照实验用）。
    private static final long T_FALLBACK = 65537L;
    private static final int BASE_BITS_FALLBACK = 16;
    private static final long SEED = 20261013L;
    private static final String ASCII = "ASCII";

    // ---- loaded once at startup ----
    private CapeDemoData db;
    private CapeDemoData.Tables tb;
    private long ctxHandle = -1;
    private long[] tableFlat;
    private final long setupJavaMs;
    private final long setupNativeMs;
    private final String setupAt;
    private final int n;
    private final int d;
    private final int port;
    private final long t;
    private final int baseBits;
    /** SETUP 时标定出来的「一个单元」耗时（ms）；<=0 表示标定失败、已回退。 */
    private final double unitMsMeasured;

    /**
     * <b>打分信道</b>（CAPE A2 ANSWER 4-8）。它的明文模数恒为
     * {@link CapeBloomScore#SCORE_T}（65537），<b>与 {@link #t} 不同</b> —— 见构造器里那段说明。
     *
     * <p>{@code -Dcape.nocape=true} 可跳建（把 SETUP 省下约 1.5 s，用于快速冒烟）。
     */
    private final BloomChannel.Scorer scorer;
    private final long scoreSetupMs;

    // ---- last query, for polling ----
    private final AtomicBoolean busy = new AtomicBoolean(false);
    private final AtomicReference<String> lastResult = new AtomicReference<>("{}");
    private volatile String currentKws = "";

    private CapeDemoService(int port, int n, int d, CapeDemoData db) throws IOException {
        this.port = port;
        this.n = n;
        this.d = d;
        this.db = db;
        this.t = resolveT(db);
        this.baseBits = resolveBaseBits(db, this.t);

        int maxValues = db.intMeta("maxValues", 3);
        int kwTotal = db.keywords.size();
        int cellsPerCol = FusePirSetup.cellsPerCol(R, maxValues);
        int C = Math.max(1, (kwTotal + cellsPerCol - 1) / cellsPerCol);

        long j0 = System.nanoTime();
        this.tb = db.buildTables(n, C, R, K, this.t, SEED);
        this.tableFlat = CapeDemoSetupProbe.flatten(tb.p, n, tb.bPay);
        this.setupJavaMs = (System.nanoTime() - j0) / 1_000_000;

        // 打分信道（CAPE Algorithm 2 的 ANSWER 4-8）：它必须跑在 t=65537 上，
        // 因为 BatchEncoder 要求 t ≡ 1 (mod 2N)，而库里的 t=2^32 连素数都不是
        // （实测：new BatchEncoder 直接抛 "not valid for batching"，见 CapeScoreChannelProbe）。
        // 所以本服务持有**两个** SEAL 上下文：native 的（t=库里值，跑盲旋转）
        // 与 Java 的（t=65537，跑加密 Bloom 打分）。这是一处必须写进报告的口径差。
        long s0 = System.nanoTime();
        this.scorer = Boolean.getBoolean("cape.nocape") ? null : BloomChannel.setup(n);
        this.scoreSetupMs = (System.nanoTime() - s0) / 1_000_000;

        long n0 = System.nanoTime();
        this.ctxHandle = NativeBlindRotate.nativeCreateContext(n, this.t, this.baseBits);
        long kh = NativeBlindRotate.nativeBuildBootstrapKey(ctxHandle, d);
        NativeBlindRotate.nativeDestroyKey(kh);   // nativeCapeAnswer rebuilds it per call
        this.setupNativeMs = (System.nanoTime() - n0) / 1_000_000;
        this.setupAt = java.time.LocalDateTime.now().toString();

        // 在 SETUP 里顺手标定一次「每个单元多久」。这是为了让前端首屏能显示
        // **本配置的真实预期**，而不是某份会过期的硬编码基线 —— 之前前端写 154 000、
        // README 写 176 000、实际最快 102 000，三份数互相矛盾就是因为没人在跑之前知道真值。
        // 约 10 轮盲旋转，几百毫秒，且 SETUP 本来就并排单独显示、不计入查询耗时。
        this.unitMsMeasured = measureUnitMs();
    }

    /**
     * {@code t} 取 {@code meta.plainModulus}（建库时写下的），JVM 开关可覆盖。
     *
     * <p>为什么要从库里读：载荷断言（{@code CapeDemoData} 里 payload 每个系数 &lt; t）
     * 和表构造都依赖 t，而 t 同时决定 gadget 基能开多大。硬编码在服务里就有
     * 「库和服务不一致」的隐患，而且这个隐患是**静默**的（载荷被 mod t 截断）。
     */
    private static long resolveT(CapeDemoData db) {
        long fromDb = db.longMeta("plainModulus", T_FALLBACK);
        Long forced = Long.getLong("cape.t");
        if (forced != null && forced != fromDb) {
            System.out.println("[warn] -Dcape.t=" + forced + " 覆盖了库里的 plainModulus="
                + fromDb + "；载荷系数必须 < t，不一致会导致静默截断");
        }
        return forced != null ? forced : fromDb;
    }

    /**
     * gadget 基位宽：优先 {@code meta.baseBits}（建库时定），否则按 {@code base < 2t}
     * 推一个安全值 —— 平衡分解的位要落在 {@code [0, t)} 内，所以 base 的上限由 t 定。
     * 最大值 32（{@code base = 2^32} 的平衡位正好放得进 {@code t = 2^32}）。
     */
    private static int resolveBaseBits(CapeDemoData db, long t) {
        Integer forced = Integer.getInteger("cape.b");
        if (forced != null) {
            return forced;
        }
        int fromDb = db.intMeta("baseBits", 0);
        if (fromDb > 0) {
            return fromDb;
        }
        // 没写就按 t 推：取满足 2^b < 2t 的最大 b，且不超过 32
        int b = 1;
        while (b < 32 && (1L << (b + 1)) < 2 * t) {
            b++;
        }
        return Math.min(b, 32);
    }

    // ------------------------------------------------------------------
    //  query
    // ------------------------------------------------------------------

    /**
     * <b>服务器侧 ANSWER</b>：只接受**密文查询**，全程不接触任何明文关键词。
     *
     * <p>这是逐子程序核对里 <b>D1</b> 的修复。旧版这个入口收的是
     * {@code List<String> kws}（明文关键词），然后在服务器进程里
     * {@code tb.kwIndex.get(...)} 查锚点、{@code bloomBits(others)} 算 Bloom 位 ——
     * 协议里有一条明文信道，论文 Appendix D.2 的混合论证不成立。
     *
     * <p>现在服务器只看到：
     * <ul>
     *   <li>{@code colIdx[a]} / {@code rowIdx[a]}：**不透明的位置**，由公开哈希 {@code H}
     *       在客户端算出（论文 pp 里 {@code H} 本来就是公开参数）；</li>
     *   <li>{@code av[a][i]} / {@code betav[a]}：行选择子的 LWE 分量
     *       （{@code β = ⟨a,s_L⟩ + r_a (mod 2N)}）；</li>
     *   <li>{@code qBfSlots}：加密的 Bloom 查询向量（本轮只接收，D2 的接入口）。</li>
     * </ul>
     * 关键词集合与 {@code τ} **从不进入这个函数**。
     */
    private String runQuerySealed(CapeQuery.Sealed q) {
        long total0 = System.nanoTime();
        long q0 = System.nanoTime();
        long queryUs = (System.nanoTime() - q0) / 1_000;   // QUERY 已在客户端完成

        // ---------- ANSWER ----------
        long a0 = System.nanoTime();
        long[] rec;
        try {
            if (q.selBlob != null) {
                // P1-1：列选择子是**客户端密文**（论文 A1 QUERY 5 的 q^col_a）。
                // 服务器只 load + multiply_plain，看不到 c_a。走的是与基线
                // **同一段 native 循环体**（cape_answer_core），所以载荷可直接比对。
                rec = NativeBlindRotate.nativeCapeAnswerSealedC(ctxHandle, d, tb.c, K, tb.bPay,
                    tableFlat, q.selBlob, q.a, q.beta, q.sBits);
            } else {
                rec = NativeBlindRotate.nativeCapeAnswerSealed(ctxHandle, d, tb.c, K, tb.bPay,
                    tableFlat, q.colIdx, q.rowIdx, q.a, q.beta, q.sBits);
            }
        } catch (Throwable t) {
            return err("native answer failed: " + t);
        }
        long answerUs = (System.nanoTime() - a0) / 1_000;

        // ---------- DECODE（服务器只回载荷，判定权在客户端）----------
        // 论文 A2 DECODE L1072-1082 的判定（指纹 ⊥ 检查 + s_j = τ）**属于客户端**：
        // 它需要 sk、需要 τ，两者都在客户端。这里只做「载荷完整性」自检（单进程回环的
        // 调试便利），不据此过滤结果 —— 过滤由 CapeSealedFlowTest 在客户端侧做。
        long d0 = System.nanoTime();
        int bPay = tb.bPay;
        long[] payloadOut = new long[bPay];
        System.arraycopy(rec, 0, payloadOut, 0, bPay);
        long decodeUs = (System.nanoTime() - d0) / 1_000;
        long totalUs = (System.nanoTime() - total0) / 1_000;

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        // ⚠️ 服务器**回显**的只有它本来就收到的位置，没有关键词
        //    （P1-1 下 colIdx 是空的 —— 服务器确实没有它）
        out.put("colIdx", q.colIdx);
        out.put("rowIdx", q.rowIdx);
        out.put("columnSelector", q.selBlob != null ? "ciphertext (P1-1)" : "plaintext colIdx (baseline)");
        out.put("payload", payloadOut);
        // ⚠️ 同一个诚实性问题：这个字段也是**明文载荷**（回环里服务端解的密）。
        //    名字 payload 不声称是密文，所以不改名，但必须附注 —— 见 payloadPlainNote。
        out.put("payloadNote", payloadPlainNote());
        Map<String, Object> timing = new LinkedHashMap<>();
        // Reported in MICROseconds: QUERY and DECODE are sub-millisecond, so rounding
        // them to whole ms would display a misleading 0 and look like a bug.
        timing.put("queryUs", queryUs);
        timing.put("answerUs", answerUs);
        timing.put("decodeUs", decodeUs);
        timing.put("totalUs", totalUs);
        timing.put("queryMs", queryUs / 1000.0);
        timing.put("answerMs", answerUs / 1000.0);
        timing.put("decodeMs", decodeUs / 1000.0);
        timing.put("totalMs", totalUs / 1000.0);
        timing.put("setupMsLast", setupJavaMs + setupNativeMs);
        timing.put("unitCount", K * tb.bPay);
        timing.put("note", "setupMsLast is NOT included in totalMs");
        out.put("timing", timing);
        return Json.write(out);
    }

    // ------------------------------------------------------------------
    //  CAPE Algorithm 2 的增量（规划书 P0-1 ~ P0-4）
    // ------------------------------------------------------------------

    /**
     * <b>论文 A2 ANSWER 4-8</b>：对锚检索出来的载荷，逐候选算出<b>密文分数</b>。
     *
     * <p>与 {@link #runQueryLegacy} 里那段「明文合取」的区别就是 CAPE 与 BKPIR 的分界：
     * 论文 §1 原文说 BKPIR "incurs prohibitively high communication overhead, requiring
     * the client to communicate the entire database for each query" —— 而 CAPE 的做法是
     * <b>服务端把候选的 Bloom 段打成一条槽位密文、同态算出得分</b>，客户端只解一条密文。
     *
     * <p>本方法返回的每一条候选都带自己的 {@code ct_score,j}（P0-2），
     * 判定权在客户端（P0-3）。
     *
     * @param qBF     客户端给的 {@code q_BF}（{@code RLWE.Enc(b_qry)}），
     *                槽位域；服务端**看不到** {@code b_qry} 本身
     * @param payload 锚检索解出来的载荷（{@code B_pay} 个系数）
     */
    private CapeAnswer.Answer answerCape(edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext qBF,
                                                 long[] payload) {
        return CapeAnswer.answer(scorer, qBF, payload, tb.maxValues, tb.lBf, t);   // t 定 fp 占几个槽
    }

    /**
     * <b>{@code /api/query} 的默认路径（2026-10-14 切换）</b>：收客户端的 <b>{@code q_BF} 密文</b>，
     * 跑完整 Algorithm 2，把 <b>{@code ct_score,j} 的字节</b>回给客户端判定。
     *
     * <p>与 {@link #runQueryCape} 的关系：<b>本方法才是正式实现</b>，
     * {@code runQueryCape}（收明文 {@code d2PlaintextBf}）现在只是把明文包成密文之后
     * 调本方法，供老探针沿用。两者共用同一条服务端实现，不存在第二份打分代码。
     *
     * <h3>关闭的那条明文信道（D12）</h3>
     * 旧路径：客户端算 {@code b_qry} → 发<b>明文位向量</b> → 服务器自己
     * {@code encryptQuery}。那条信道等于交出查询关键词（`CapeBfLeakProbe` 实测可唯一反解）。
     * 现在：客户端自己加密 + 自己序列化（{@link CapeBloomScore#encryptQueryWire}），
     * 服务器只拿到字节 ⇒ {@code b_qry} 全程不出客户端。
     *
     * <h3>服务端仍然看不到的东西</h3>
     * {@code b_qry}、{@code τ}、关键词 —— 一个都没有。{@code τ} 只在客户端，
     * 判定（`Dec(ct_score) == τ`）也只在客户端。
     *
     * @param req 请求体，必须含 {@code qBFBytes}（{@code q_BF} 的序列化字节）
     */
    private String runQueryCapeSealed(Map<String, Object> req) {
        long total0 = System.nanoTime();
        if (scorer == null) {
            return err("打分信道未建（-Dcape.nocape=true 启动时不会建）");
        }
        Object qbfObj = req.get("qBFBytes");
        // ⚠️ 两种形态都要收：
        //   * 走 HTTP 时是 List（JSON 数组解出来的）；
        //   * 走**进程内**自检时是 long[]（自检直接把数组放进 Map，不过 JSON）。
        // 第一版只判 `instanceof List`，于是进程内自检报"缺少 qBFBytes"而键明明在
        // （实测类型是 `[J`）—— 这类"两种调用形态不一致"的坑在混合编排里很常见。
        long[] qbfWire;
        if (qbfObj instanceof long[]) {
            qbfWire = (long[]) qbfObj;
        } else if (qbfObj instanceof List) {
            try {
                qbfWire = toLongs(qbfObj);
            } catch (RuntimeException e) {
                return err("qBFBytes 解析失败: " + e);
            }
        } else {
            return err("qBFBytes 不可用：键存在=" + req.containsKey("qBFBytes")
                + " 类型=" + (qbfObj == null ? "null" : qbfObj.getClass().getName())
                + "（默认路径收的是 q_BF 的密文字节，客户端用 "
                + "BloomChannel.encryptQueryWire 生成）");
        }

        // ---------- 锚查询 q_anc（论文 Alg 2 ANSWER 2）----------
        // ⚠️ 2026-10-14 晚修正：这里以前**不看客户端要查什么**，直接读关键词 0。
        //    现在要么客户端给锚位置，要么显式开 -Dcape.fixedAnchor=true 承认用的是固定锚。
        long[] anchorCol = req.containsKey("anchorColIdx") ? toLongs(req.get("anchorColIdx")) : null;
        long[] anchorRow = req.containsKey("anchorRowIdx") ? toLongs(req.get("anchorRowIdx")) : null;
        String anchorHow;
        if (anchorCol != null && anchorCol.length > 0
            && anchorRow != null && anchorRow.length > 0) {
            anchorHow = "client-supplied anchorColIdx/anchorRowIdx"
                + "（由公开哈希 H 算出的位置；基线形态：LWE 索引仍由服务端自造）";
        } else if (Boolean.getBoolean("cape.fixedAnchor")) {
            anchorCol = new long[] { tb.colOf[0] };
            anchorRow = new long[] { tb.rowOf[0] };
            anchorHow = "FIXED keyword #0 —— 演示捷径，由 -Dcape.fixedAnchor=true 显式开启；"
                + "**不是**答案客户端查询的锚";
        } else {
            return err("缺少锚查询：请求体既没有 anchorColIdx/anchorRowIdx，也没开 "
                + "-Dcape.fixedAnchor=true。论文 Alg 2 ANSWER 2 是 "
                + "resp_anc ← FusePIR.Answer(st_S, q_anc)，没有 q_anc 就没有锚检索 —— "
                + "本出口不再静默读关键词 #0（那会让任意锚的查询都返回 ⊥，"
                + "却让演示池第 0 组看起来是绿的）。");
        }

        // ---------- 服务器 ANSWER：锚检索（native）----------
        long a0 = System.nanoTime();
        long[] payload = runAnchorNative(anchorCol, anchorRow);
        if (payload == null) {
            return err("锚检索失败（见服务端日志）");
        }
        long anchorUs = (System.nanoTime() - a0) / 1_000;

        // ---------- 服务器 ANSWER 4-8：加密 Bloom 打分 ----------
        long s0 = System.nanoTime();
        edu.alibaba.mpc4j.crypto.fhe.seal.Ciphertext qBF;
        try {
            qBF = ScorerWire.deserialize(scorer, qbfWire);
        } catch (RuntimeException e) {
            return err("q_BF 反序列化失败（打分信道参数必须与客户端一致：N=" + n
                + "、scoreT=" + BloomChannel.SCORE_T + "）: " + e);
        }
        CapeAnswer.Answer ans = answerCape(qBF, payload);
        long scoreUs = (System.nanoTime() - s0) / 1_000;
        long totalUs = (System.nanoTime() - total0) / 1_000;

        // ---------- 回包 ----------
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("sealed", true);
        out.put("fingerprint", ans.fingerprint);
        out.put("valueCount", ans.valueCount);

        // ⚠️ 2026-10-14：**这里原先发的是明文候选值 `valueId`** —— 违反论文 §4.1 的
        //    原文要求："Only the **encrypted** candidate values and these scores are
        //    returned to the client." 现在改为只发 `ct_v`（= 载荷本身）。
        //
        //    为什么载荷就是 ct_v：`nativeCapeAnswer` 返回的 `rec[b]` 就是第 b 路的
        //    `SampleExtract_0` 解密结果，也就是 `ct_{v_j}` 解出来的那一个载荷系数。
        //    DECODE 第 2 行 `V_{K1} ← FusePIR.Decode(...)` 做的正是"把这 B_pay 个
        //    系数解出来、按载荷布局取出值列表" —— 所以客户端**自己就能算出** `{v_j}`，
        //    **不需要、也不该**让服务器把候选值的身份告诉它。
        //
        //    ⚠️ 如实说明它的边界：单进程回环里服务端**本来就有**这张表（它知道
        //    "第 0 个关键词的候选是谁"），所以这一步**不是**在回环里新增了隐私 ——
        //    它去掉的是一条**不必要的明文信道**，并让客户端的数据流与论文一致
        //    （客户端从 `ct_v` 自己解出 `{v_j}`）。真部署里它才是承重的。
        // ⚠️ 2026-10-14 晚：**字段从 ctPay 改名为 payloadPlain**。
        //    原名声称这是密文（"ct_v"），而 runAnchorNative 返回的是**解密结果**；
        //    载荷布局 [0]=指纹, [1]=候选数, 之后每候选 1+ℓ_BF 项（第 1 项是 value id）
        //    ⇒ 上一轮"不再发明文 valueId"在回环里是名义上的，同样的 id 还在这份响应里。
        //    改名 + 附注是为了让这件事无法被读漏；真修（发真密文）要等 Pack 的决定。
        out.put("payloadPlain", payload);
        out.put("payloadPlainNote", payloadPlainNote());
        out.put("anchor", anchorHow);

        // 每候选一组（P0-2）。**刻意不发任何明文分数**：发了就等于把判定绕过去。
        // 每条候选各带自己的 ct_score,j 字节 —— 客户端逐条解、逐条判定。
        List<Object> cands = new ArrayList<>();
        List<Long> ctScoreLens = new ArrayList<>();
        for (CapeAnswer.Cand c : ans.candidates) {
            long[] bytes = ScorerWire.serialize(c.ctScore);
            Map<String, Object> one = new LinkedHashMap<>();
            // ⚠️ 只放密文长度（公开的元信息），**不放 valueId**
            one.put("ctScoreBytes", bytes);
            cands.add(one);
            ctScoreLens.add((long) bytes.length);
        }
        out.put("candidates", cands);
        out.put("candidateCount", ans.candidates.size());
        out.put("ctScoreBytesLen", ctScoreLens);
        Map<String, Object> timing = new LinkedHashMap<>();
        timing.put("anchorUs", anchorUs);
        timing.put("scoreUs", scoreUs);
        timing.put("totalUs", totalUs);
        timing.put("anchorMs", anchorUs / 1000.0);
        timing.put("scoreMs", scoreUs / 1000.0);
        timing.put("totalMs", totalUs / 1000.0);
        timing.put("unitCount", K * tb.bPay);
        timing.put("scoreSetupMs", scoreSetupMs);
        out.put("timing", timing);
        out.put("scoreChannel", scoreChannelNote());
        out.put("decodeNote", "判定在客户端：f == fp(K) 且 s_j = Dec(ct_score,j) == tau 才收；"
            + "候选值由客户端从 payloadPlain 自己解出（**该字段是明文**，见 payloadPlainNote）。"
            + "服务端没发过 tau、没发过明文分数、也没发过候选值的 id");
        return Json.write(out);
    }

    /**
     * <b>{@code /api/query-cape}</b>：Algorithm 2 的服务器侧出口。
     *
     * <p>⚠️ <b>2026-10-14 起它不是正式路径。</b>它收的是 {@code b_qry} 的<b>明文</b>槽向量
     * （{@code d2PlaintextBf}），只为了让 P0 阶段的探针能单独验证 ANSWER 4-8 那一段。
     * 正式路径是 {@code /api/query} 的 {@code qBFBytes}（见 {@link #runQueryCapeSealed}）。
     *
     * <p>保留它是因为 {@code CapeAlgorithm2Diag} 靠它做端到端；它内部**把明文包成
     * 密文之后调用同一个实现**，所以没有第二份打分代码。真部署应关掉这个口
     * （字段名带 {@code d2} 前缀就是为了让它无法被误认为正式协议）。
     */
    private String runQueryCape(Map<String, Object> req) {
        if (scorer == null) {
            return err("打分信道未建（-Dcape.nocape=true 启动时不会建）");
        }
        Object bfObj = req.get("d2PlaintextBf");
        if (!(bfObj instanceof List)) {
            return err("缺少 d2PlaintextBf（本出口是 P0 阶段的明文包密文通道，"
                + "正式路径请用 /api/query 的 qBFBytes）");
        }
        List<?> rawBf = (List<?>) bfObj;
        if (rawBf.size() != tb.lBf) {
            return err("d2PlaintextBf 长度 " + rawBf.size() + " != l_BF " + tb.lBf);
        }
        boolean[] bQry = new boolean[tb.lBf];
        for (int i = 0; i < tb.lBf; i++) {
            bQry[i] = ((Number) rawBf.get(i)).longValue() != 0;
        }
        // 包成密文之后走**同一条**正式实现
        Map<String, Object> wrapped = new LinkedHashMap<>();
        wrapped.put("qBFBytes", BloomChannel.encryptQueryWire(scorer, bQry));
        // ⚠️ 锚位置要**透传**：runQueryCapeSealed 现在（2026-10-14 晚起）强制要锚查询，
        //    不再静默读关键词 #0。本出口的调用方要么在这条请求里带上
        //    anchorColIdx/anchorRowIdx，要么显式开 -Dcape.fixedAnchor=true。
        if (req.containsKey("anchorColIdx")) {
            wrapped.put("anchorColIdx", req.get("anchorColIdx"));
        }
        if (req.containsKey("anchorRowIdx")) {
            wrapped.put("anchorRowIdx", req.get("anchorRowIdx"));
        }
        return runQueryCapeSealed(wrapped);
    }

    /**
     * 跑一次 native 锚检索，返回载荷（<b>已解密</b>，见 {@link #payloadPlainNote()}）。
     *
     * <h3>⚠️ 2026-10-14 晚修正：这里以前**写死读第 0 个关键词**</h3>
     *
     * 旧版不管客户端查什么，都用 {@code tb.colOf[0]} / {@code tb.rowOf[0]} ——
     * 而那正是论文 Algorithm 2 ANSWER 第 2 行要的 `q_anc` **根本不存在**的表现：
     * 客户端连锚查询都没发（旧请求体只有 {@code {"d",…,"qBFBytes":[…]}}）。
     *
     * <p>后果是默认路径**只能回答"锚 = DB 第 0 个关键词"的查询**；别的锚会因
     * {@code f = fp(关键词0) ≠ fp(K)} 被指纹校验挡下（<b>响亮失败，不是静默出错</b>，
     * 这要谢谢 P0-4）。而 {@code selftestCape} / {@code CapeDefaultPathTest} 的绿灯，
     * 是"演示池第 0 组恰好以关键词 0 为锚"换来的，不是协议能力。
     *
     * <p>现在锚位置由**客户端**给出。{@code colIdx}/{@code rowIdx} 由公开哈希 {@code H}
     * 算出（见 {@code CapeQuery.keywordHash}），所以任何客户端都算得出；
     * 而 {@code β} 需要与累加器同一把秘密（回环限制），所以这里走
     * {@code nativeCapeAnswer} 这条**基线形态**（服务器自造 LWE 索引）。
     * <b>⇒ 这次修正只关掉"写死关键词 0"，不关掉 D3/N5 的 {@code (c_a, r_a)} 可还原</b>
     * —— 那是 P1-1（已做）/ P1-2（未做）的事。
     *
     * @param colIdx 客户端给的列号（长度 ≥1；不足 K 项时按最后一项补齐）
     * @param rowIdx 客户端给的行号（同规则）
     */
    private long[] runAnchorNative(long[] colIdx, long[] rowIdx) {
        long[] cIdx = new long[K];
        long[] rIdx = new long[K];
        for (int a = 0; a < K; a++) {
            cIdx[a] = colIdx[Math.min(a, colIdx.length - 1)];
            rIdx[a] = rowIdx[Math.min(a, rowIdx.length - 1)];
        }
        try {
            return NativeBlindRotate.nativeCapeAnswer(ctxHandle, d, tb.c, K, tb.bPay,
                tableFlat, cIdx, rIdx);
        } catch (Throwable t) {
            System.out.println("[error] 锚检索失败: " + t);
            return null;
        }
    }

    /**
     * 把「{@code payloadPlain} 是**明文**」这件事写进响应，免得被当成密文读漏。
     *
     * <p>2026-10-14 晚修正：这个字段以前叫 {@code ctPay}，而它的值是
     * {@code nativeCapeAnswer} 的**解密结果** —— <b>名字声称是密文，值是明文</b>，
     * 而且载荷布局 `[0]=指纹, [1]=候选数, 之后每候选 1+ℓ_BF 项（第 1 项是 value id）`
     * 里就装着候选值的 id。
     * ⇒ 上一轮"响应里不再发明文 valueId"那个修复，在本回环里是**名义上的**：
     * 同样的 id 仍在同一份响应里，只是搬进了载荷数组。改名是为了让这件事无法被读漏。
     *
     * <p>论文这一段的原文是 {@code Alg 1 DECODE 2-4: y[β] ← Dec_{s_R}(ct_{pay,β})}
     * —— 解密是**客户端**做的，服务端返回的是密文。要真修就得发 B_pay 条密文
     * （按实测单条 524,401 字节推算约 **30.9 MB/响应**，是推算不是实测），
     * 而 Pack 存在的意义正是把它压成几条 ⇒ <b>真修要等 Pack 的架构决定</b>。
     */
    private static Map<String, Object> payloadPlainNote() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("is", "plaintext");
        m.put("why", "单进程回环：服务端持有 native 上下文秘密，锚检索的解密就在服务端做完了");
        m.put("paper", "论文 Alg 1 DECODE 2-4 是客户端做 Dec_{s_R}，服务端resp_anc 是密文；"
            + "§4.1 要求返回的是 encrypted candidate values");
        m.put("realFix", "要发 B_pay 条密文（约 30.9 MB/响应，按实测单条 524,401 字节推算）"
            + "⇒ 真修要等 Pack 的架构决定，见 docs/reports/伪代码逐行复核-两处硬偏离-2026-10-14.md");
        m.put("renamed", "本字段 2026-10-14 晚从 ctPay 改名 —— 原名声称是密文，值是明文");
        return m;
    }

    /** 把「打分信道与 native 信道不是同一个 t」这条口径差写进响应，免得被读漏。 */
    private Map<String, Object> scoreChannelNote() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("nativeT", t);
        m.put("scoreT", BloomChannel.SCORE_T);
        m.put("why", "BatchEncoder 要求 t ≡ 1 (mod 2N)；t=2^32 下 new BatchEncoder 直接抛 "
            + "\"encryption parameters are not valid for batching\"（实测 CapeScoreChannelProbe）");
        m.put("keys", "两条信道各持一把独立 sk（单进程回环里同一个 JVM 持有两把）");
        m.put("honest", "论文只有一把 sk、一个 t；这是本实现的口径差，必须一起报");
        return m;
    }

    private String runQueryLegacy(List<String> kws) {        long total0 = System.nanoTime();

        // ---------- QUERY ----------
        long q0 = System.nanoTime();
        List<String> unknown = new ArrayList<>();
        for (String k : kws) {
            if (!tb.kwIndex.containsKey(k)) {
                unknown.add(k);
            }
        }
        if (!unknown.isEmpty()) {
            return err("unknown keyword(s): " + unknown);
        }
        // anchor = first keyword; the rest go into b_qry
        int anchorIdx = tb.kwIndex.get(kws.get(0));
        List<String> others = new ArrayList<>(kws.subList(1, kws.size()));
        boolean[] bQry = bloomBits(others);
        long tau = 0;
        tau = BfGen.hammingWeight(bQry);
        long[] cIdx = new long[K];
        long[] rIdx = new long[K];
        for (int a = 0; a < K; a++) {
            cIdx[a] = tb.colOf[anchorIdx];
            rIdx[a] = tb.rowOf[anchorIdx] + a;
        }
        long queryUs = (System.nanoTime() - q0) / 1_000;   // QUERY is usually sub-ms

        // ---------- ANSWER ----------
        long a0 = System.nanoTime();
        long[] rec;
        try {
            rec = NativeBlindRotate.nativeCapeAnswer(ctxHandle, d, tb.c, K, tb.bPay,
                tableFlat, cIdx, rIdx);
        } catch (Throwable t) {
            return err("native answer failed: " + t);
        }
        long answerUs = (System.nanoTime() - a0) / 1_000;

        // ---------- DECODE ----------
        long d0 = System.nanoTime();
        long[] want = tb.payload[anchorIdx];
        int bad = 0;
        for (int b = 0; b < tb.bPay; b++) {
            if (rec[b] != want[b]) {
                bad++;
            }
        }
        long fp = rec[0];
        long fpWant = want[0];
        int count = (int) rec[1];
        List<Object> results = new ArrayList<>();
        int lookups = tb.maxValues;
        for (int j = 0; j < lookups && j < count; j++) {
            int base = 2 + j * (1 + tb.lBf);
            int valueId = (int) rec[base];
            if (valueId <= 0) {
                continue;
            }
            boolean[] bv = new boolean[tb.lBf];
            for (int bi = 0; bi < tb.lBf; bi++) {
                bv[bi] = rec[base + 1 + bi] != 0;
            }
            // conjunction test: every query bit must also be set on this value
            boolean conj = true;
            for (int bi = 0; bi < tb.lBf; bi++) {
                if (bQry[bi] && !bv[bi]) {
                    conj = false;
                    break;
                }
            }
            if (conj) {
                Map<String, Object> one = new LinkedHashMap<>();
                one.put("valueId", valueId);
                one.put("title", db.title(valueId));
                one.put("rawMovieId", db.rawMovieId(valueId));
                results.add(one);
            }
        }
        long decodeUs = (System.nanoTime() - d0) / 1_000;
        long totalUs = (System.nanoTime() - total0) / 1_000;

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", true);
        out.put("keywords", kws);
        out.put("anchor", kws.get(0));
        out.put("tau", tau);
        out.put("hit", !results.isEmpty());
        out.put("results", results);
        out.put("valueCount", count);
        Map<String, Object> timing = new LinkedHashMap<>();
        // Reported in MICROseconds: QUERY and DECODE are sub-millisecond, so rounding
        // them to whole ms would display a misleading 0 and look like a bug.
        timing.put("queryUs", queryUs);
        timing.put("answerUs", answerUs);
        timing.put("decodeUs", decodeUs);
        timing.put("totalUs", totalUs);
        timing.put("queryMs", queryUs / 1000.0);
        timing.put("answerMs", answerUs / 1000.0);
        timing.put("decodeMs", decodeUs / 1000.0);
        timing.put("totalMs", totalUs / 1000.0);
        timing.put("setupMsLast", setupJavaMs + setupNativeMs);
        timing.put("unitCount", K * tb.bPay);
        timing.put("note", "setupMsLast is NOT included in totalMs");
        out.put("timing", timing);
        // ⚠️ 2026-10-14 改名并说清证明力。旧字段名 `integrity` 被高估了：
        // 它比对的只是「解密回来的载荷 == 明文载荷」，覆盖 share 重建 + 列选择 +
        // 行盲旋转 + 解密；**完全不含合取逻辑**（legacy 的合取是下面的明文
        // `boolean conj`），更不含同态得分——agent 路径里根本没有得分。
        // 但 `integrity` 与 hit/results 并排出现，读起来像"整条链已验"，所以改成一个
        // 不夸大、也仍然是合法 JSON 标识符的名字；旧名保留为同值别名字段，避免打断前端。
        boolean payloadRoundTrip = (bad == 0 && fp == fpWant);
        out.put("payloadRoundTrip", payloadRoundTrip);
        out.put("integrity", payloadRoundTrip);   // 兼容别名
        out.put("payloadMismatch", bad);
        out.put("payloadRoundTripNote",
            "只证明「三路 share 重建 + 列选择 + 行盲旋转 + 解密」正确；"
                + "不含合取判定，也不含同态得分（两者本路径未实现）");
        return Json.write(out);
    }

    /** BF.Gen over the non-anchor query keywords (client side). */
    private boolean[] bloomBits(List<String> kws) {
        com.fusepir.common.BfGen g = com.fusepir.common.BfGen.choose(
            db.intMeta("maxSetSize", 4), eps(), n);
        if (g.length() != tb.lBf) {
            throw new IllegalStateException("l_BF mismatch: " + g.length() + " vs " + tb.lBf);
        }
        return g.bits(kws);
    }

    private double eps() {
        Object v = db.meta.get("epsBf");
        return v instanceof Number ? ((Number) v).doubleValue() : Math.pow(2, -6);
    }

    private static String err(String msg) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", false);
        m.put("error", msg);
        return Json.write(m);
    }

    // ------------------------------------------------------------------
    //  HTTP
    // ------------------------------------------------------------------

    private void start() throws IOException {
        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        srv.setExecutor(Executors.newFixedThreadPool(4));
        srv.createContext("/api/state", this::hState);
        srv.createContext("/api/query", this::hQuery);
        // 合规路径：客户端构造密文查询后再发，服务器不接触明文关键词（修 D1）
        srv.createContext("/api/query-sealed", this::hQuerySealed);
        // CAPE Algorithm 2 的增量出口（G1 加密 Bloom 打分 + G2 每候选密文分数）。
        // 独立出口，不动 /api/query —— 见规划书 P0-1 的回滚要求。
        srv.createContext("/api/query-cape", this::hQueryCape);
        // P1-1 的进程内验收入口：列选择子改客户端加密（要进程内上下文句柄，
        // 所以只能在服务里跑；默认关闭，见 hColumnSelftest）。
        srv.createContext("/api/selftest/column", this::hColumnSelftest);
        // P2-1 第一步：量每列成本（明文 NTT 那一行的载体）。同样要进程内上下文。
        srv.createContext("/api/selftest/ntt-share", this::hNttShare);
        srv.createContext("/api/pool", this::hPool);
        srv.createContext("/", this::hStatic);
        srv.start();

        System.out.printf("%n=== CAPE demo service ready ===%n");
        System.out.printf("  open  http://127.0.0.1:%d/%n", port);
        System.out.printf("  SETUP: java %d ms + native %d ms = %d ms%n",
            setupJavaMs, setupNativeMs, setupJavaMs + setupNativeMs);
        System.out.printf("  N=%d d=%d C=%d R=%d k=%d B_pay=%d units=%d%n",
            n, d, tb.c, R, K, tb.bPay, K * tb.bPay);
    }

    private void hState(HttpExchange ex) throws IOException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ready", true);
        m.put("busy", busy.get());
        m.put("currentKws", currentKws);
        Map<String, Object> setup = new LinkedHashMap<>();
        setup.put("done", true);
        setup.put("ms", setupJavaMs + setupNativeMs);
        setup.put("javaMs", setupJavaMs);
        setup.put("nativeMs", setupNativeMs);
        setup.put("at", setupAt);
        m.put("setup", setup);
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("N", n);
        params.put("t", t);
        params.put("baseBits", baseBits);
        params.put("levels", levelsOf(ctxHandle));
        params.put("d", d);
        params.put("C", tb.c);
        params.put("R", R);
        params.put("k", K);
        params.put("maxValues", tb.maxValues);
        params.put("maxSetSize", db.intMeta("maxSetSize", 4));
        params.put("lBf", tb.lBf);
        params.put("bPay", tb.bPay);
        params.put("unitCount", K * tb.bPay);
        params.put("epsBf", eps());
        // 打分信道（CAPE A2 ANSWER 4-8）的参数：它的 t 与上面那个 t 不同，必须分开报，
        // 否则客户端会拿到错误的模数去造 q_BF（那会静默解出垃圾）。
        params.put("scoreT", BloomChannel.SCORE_T);
        params.put("scoreSlots", scorer == null ? -1 : scorer.slots);
        params.put("scoreReady", scorer != null);
        params.put("scoreSetupMs", scoreSetupMs);
        m.put("params", params);
        // 客户端要能自解释地知道"哪条是正式路径、请求体该带什么"，
        // 而不是靠读文档或猜。这一段就是协议自述。
        Map<String, Object> proto = new LinkedHashMap<>();
        proto.put("defaultPath", "POST /api/query  {\"qBFBytes\":[0..255 ...],"
            + "\"anchorColIdx\":[…], \"anchorRowIdx\":[…]}");
        proto.put("defaultPathAnchor", "**必填** anchorColIdx/anchorRowIdx —— 它们是 q_anc 里的"
            + "位置分量（论文 Alg 2 ANSWER 2 要 resp_anc ← FusePIR.Answer(st_S, q_anc)），"
            + "由公开哈希 H 算出（CapeQuery.buildIndicesOnly）。"
            + "缺了就报错：本出口不再静默读关键词 #0（那会让任意锚的查询都返回 ⊥，"
            + "却让演示池第 0 组看起来是绿的）。演示可用 -Dcape.fixedAnchor=true 显式选固定锚，"
            + "响应里的 anchor 字段会说明用的是哪种");
        proto.put("payloadPlain", "响应里的 payloadPlain 是**明文**载荷（不是密文）："
            + "单进程回环里服务端持秘密，锚检索的解密在服务端做完了。"
            + "论文 Alg 1 DECODE 2-4 是客户端做 Dec_{s_R}；真修要发 B_pay 条密文"
            + "（约 30.9 MB/响应），要等 Pack 的决定。该字段 2026-10-14 晚从 ctPay 改名"
            + "（原名声称是密文、值是明文）");
        proto.put("defaultPathDecision", "客户端 Dec(ct_score) == tau，且 f == fp(K)");
        proto.put("qbfBytesFrom", "BloomChannel.encryptQueryWire(scorer, b_qry)"
            + "（客户端侧加密，服务器只收字节）");
        proto.put("responseDecisionFields", "fingerprint, candidates[].valueId, candidates[].ctScoreBytes");
        proto.put("legacyPath", "POST /api/query  {\"keywords\":[...]} —— 明文合取判定，"
            + "保留但不含 Algorithm 2 的判定；见 docs/缺陷总表.md 的偏差 D2");
        proto.put("d2OnlyPath", "POST /api/query-cape  {\"d2PlaintextBf\":[0/1 ...]} —— "
            + "P0 阶段的明文包密文通道，正式路径不用它");
        proto.put("sealedPath", "POST /api/query-sealed  {rowIdx, aFlat, beta, sBits, "
            + "colSel+colSelLen} —— 客户端把列选择子加密后送来（P1-1），"
            + "服务器看不到 c_a；41 MB/查询，-Dcape.sealed=false 可关");
        proto.put("sealedPathBaseline", "同一个出口也收 {colIdx,...}（明文列号基线形态），"
            + "两种形态互斥发出：colSel 在则 colIdx 必定不在");
        proto.put("columnSelector", "P1-1：客户端加密 k×C 条 one-hot 选择子"
            + "（论文 A1 QUERY 4-5 的 q^col_a），服务器只 load + multiply_plain");
        proto.put("selftests", "POST /api/selftest/column（P1-1 验收：逐系数一致 + 两条负对照）、"
            + "POST /api/selftest/ntt-share；两者都要 -Dcape.selftest=true");
        m.put("protocol", proto);
        // ⚠️ 测试专用后门（默认关闭）：把打分信道的 sk 序列化出去。
        //
        // 为什么必须有它：ct_score 是用打分信道的 sk 加密的（服务端运算、客户端解密），
        // 所以**判定方必须持有与服务器同一个密钥持有者的 sk**。单进程回环里这是天然成立的，
        // 但"客户端是另一个 JVM"时它就得有个显式通道 —— 否则客户端只会解出垃圾
        // （实测 26921 而不是 0..ℓ_BF，而且**不报错**，极易被误读成"打分算错了"）。
        //
        // 它当然**不能**出现在真部署里（服务器绝不该吐 sk），所以：
        //   * 默认关闭；
        //   * 要 `-Dcape.insecure.keyecho=true` 才开；
        //   * 字段名带 insecure 前缀，让它在任何日志/抓包里都刺眼。
        if (Boolean.getBoolean("cape.insecure.keyecho") && scorer != null) {
            Map<String, Object> leak = new LinkedHashMap<>();
            leak.put("insecureScoreSecretKeyBytes",
                ScorerWire.serializeKey(scorer.secretKey()));
            leak.put("warning", "测试专用：真部署绝不能让服务器吐出 sk");
            m.put("insecureTestOnly", leak);
        }
        Map<String, Object> database = new LinkedHashMap<>();
        database.put("keywords", db.keywords.size());
        database.put("values", db.valueSpace.size());
        database.put("assoc", db.intMeta("assoc", -1));
        database.put("coveredValues", db.intMeta("covered_values", -1));
        database.put("poolSize", db.pool.size());
        m.put("db", database);
        m.put("keywords", db.keywords);
        m.put("lastResult", lastResult.get());
        m.put("expected", expected());
        // ⚠️ 这里**不能**暴露 ctxHandle：它是 native 侧裸指针，只在**本进程内**有效，
        // 跨进程传给别的 JVM 会直接段错误（我实测踩过一次）。
        // 所以合规路径的验证只能在同进程内做 —— 见 selftestSealed()。
        send(ex, 200, Json.write(m));
    }

    /**
     * 标定「一个真实单元」的耗时（ms）。
     *
     * <p><b>为什么不是测一次盲旋转再乘系数。</b>第一版是跑 8 轮 {@code nativeRunWithCtx}
     * 取平均，结果三次分别得到 289 / 290 / <b>204</b> ms/单元 —— 抖得没法用。原因是
     * 那条路径的累加器小而热、也读不到那张 {@code [C][B_pay][N]} 大表（本配置 135 MB），
     * 而真实查询里列选出来的密文要去读它。两者差 1.4~2.0× 且不稳定，乘一个固定系数是自欺。
     *
     * <p><b>改成直接跑一个真单元。</b>走的就是生产入口
     * {@code nativeCapeAnswer}，唯一改动是把 {@code bPay} 截断到 {@code k} 个载荷块
     * （只影响答案系数个数，不影响 col/row 选择子、表读取模式、CMUX 轮数）。
     * 这样量到的 ms/单元与真实查询同源。代价约 1~2 s，且只在 SETUP 里付一次。
     *
     * <p>因为同一个单元会被跑 {@code k} 条路都算一遍，而真实 ANSWER 也是
     * {@code k × bPay} 个单元，所以 {@code 耗时 / (k × 截断块数)} 直接就是 ms/单元。
     */
    private double measureUnitMs() {
        try {
            // ⚠️ 2026-10-14 改成**两点标定（测斜率）**。原因：单点探针只跑
            // probeB = k 块，而真实 ANSWER 跑 bPay 块。每次 nativeCapeAnswer 调用都有
            // **与块数无关的固定开销**（建 bootstrap key、列选择子、内存分配），
            // 单点除以块数会把这笔固定开销摊到 3 块上而不是 59 块上 ⇒ 单元被高估。
            // 实测：单点报 275 ms/单元 ⇒ 预期 48 680 ms，而端到端是 36 852 ms（偏大 32%）。
            // 用两个不同块数求斜率即可把这笔开销完全消掉，且不需要知道它是什么。
            //
            // 块数取 2 与 8（都远小于 bPay=59，所以只多花几百毫秒）：
            //     T(m) = c + m·K·unit
            //     unit = (T(8) − T(2)) / (K·(8−2))
            final int p1 = 2;
            final int p2 = Math.min(8, tb.bPay);
            if (p2 <= p1) {
                return measureUnitMsSinglePoint();
            }
            long[] cIdx = new long[K];
            long[] rIdx = new long[K];
            for (int a = 0; a < K; a++) {
                cIdx[a] = tb.colOf[0];
                rIdx[a] = tb.rowOf[0] + a;
            }
            // 预热：把 native 内存池、NTT 表、页缓存跑热，否则第一次调用会主导斜率
            NativeBlindRotate.nativeCapeAnswer(ctxHandle, d, tb.c, K, tb.bPay,
                tableFlat, cIdx, rIdx);
            long tp1 = timeProbe(p1, cIdx, rIdx);
            long tp2 = timeProbe(p2, cIdx, rIdx);
            // 再测一轮取小值，压掉调度抖动（斜率对噪声很敏感：两块之差是分母）
            long tp1b = timeProbe(p1, cIdx, rIdx);
            long tp2b = timeProbe(p2, cIdx, rIdx);
            double t1 = Math.min(tp1, tp1b) / 1e6;
            double t2 = Math.min(tp2, tp2b) / 1e6;
            double unit = (t2 - t1) / ((double) K * (p2 - p1));
            if (!(unit > 0) || !Double.isFinite(unit)) {
                System.out.println("[warn] 两点标定得到非正斜率（" + unit + "），回退单点");
                return measureUnitMsSinglePoint();
            }
            System.out.printf("[setup] 标定：一个真实单元 = %.1f ms"
                    + "（两点法：%d 块 %.0f ms vs %d 块 %.0f ms，斜率已消掉固定开销）%n",
                unit, p1, t1, p2, t2);
            return unit;
        } catch (Throwable ex) {
            System.out.println("[warn] 单元标定失败，回退到旧的一次盲旋转估计：" + ex);
            try {
                int reps = 8;
                long job = NativeBlindRotate.nativePrepare(ctxHandle, d);
                try {
                    NativeBlindRotate.nativeRunWithCtx(ctxHandle, job, 2);
                    long t0 = System.nanoTime();
                    NativeBlindRotate.nativeRunWithCtx(ctxHandle, job, reps);
                    long t1 = System.nanoTime();
                    return (t1 - t0) / 1e6 / reps;
                } finally {
                    NativeBlindRotate.nativeFreeJob(job);
                }
            } catch (Throwable ex2) {
                System.out.println("[warn] 回退也失败：" + ex2);
                return 0;
            }
        }
    }

    /** 跑一个「只算 {@code blockCount} 个载荷块」的真查询，返回纳秒耗时。 */
    private long timeProbe(int blockCount, long[] cIdx, long[] rIdx) {
        long t0 = System.nanoTime();
        NativeBlindRotate.nativeCapeAnswer(ctxHandle, d, tb.c, K, blockCount,
            tableFlat, cIdx, rIdx);
        return System.nanoTime() - t0;
    }

    /**
     * 旧的一次性单点标定（只跑 {@code k} 块）。保留作两点法的回退路径：
     * 它**偏高**（把固定开销摊到 k 块上），但在斜率算不出来时聊胜于无。
     */
    private double measureUnitMsSinglePoint() {
        final int probeB = Math.min(K, tb.bPay);
        long[] flat = CapeDemoSetupProbe.flatten(tb.p, n, tb.bPay);
        long[] cIdx = new long[K];
        long[] rIdx = new long[K];
        for (int a = 0; a < K; a++) {
            cIdx[a] = tb.colOf[0];
            rIdx[a] = tb.rowOf[0] + a;
        }
        NativeBlindRotate.nativeCapeAnswer(ctxHandle, d, tb.c, K, probeB, flat, cIdx, rIdx);
        long t0 = System.nanoTime();
        NativeBlindRotate.nativeCapeAnswer(ctxHandle, d, tb.c, K, probeB, flat, cIdx, rIdx);
        long t1 = System.nanoTime();
        double ms = (t1 - t0) / 1e6 / (K * probeB);
        System.out.printf("[setup] 标定（单点回退，偏高）：一个单元 ≈ %.1f ms"
                + "（跑 %d 路 × %d 块）%n", ms, K, probeB);
        return ms;
    }

    /**
     * 前端首屏要显示的「本配置预期」，取代前端里那份硬编码基线
     * （那份一直没跟上 README：前端写 154 000、README 写 176 000、实际最快是 102 000）。
     *
     * <p>数值 = SETUP 时**实测的一个真实单元** × 单元数。测的是生产入口
     * {@code nativeCapeAnswer}（只把载荷块截断到 k），所以读表模式、CMUX 轮数、
     * 选择子构造都与真实查询同源，不是「一次孤立盲旋转 × 修正系数」那种外推。
     */
    private Map<String, Object> expected() {
        Map<String, Object> e = new LinkedHashMap<>();
        int unitCount = K * tb.bPay;
        e.put("unitCount", unitCount);
        e.put("bPay", tb.bPay);
        e.put("d", d);
        e.put("levels", levelsOf(ctxHandle));
        if (unitMsMeasured <= 0) {
            e.put("answerMs", 0);
            e.put("source", "标定失败，无预期值");
            return e;
        }
        e.put("unitMs", Math.round(unitMsMeasured));
        e.put("answerMs", Math.round(unitCount * unitMsMeasured));
        e.put("queryUs", 320);
        e.put("decodeUs", 100);
        e.put("setupMs", setupJavaMs + setupNativeMs);
        e.put("source", "SETUP 时两点标定一个真实单元的**斜率**（nativeCapeAnswer，块数 2 vs 8）"
            + "× unitCount —— 斜率已消掉与块数无关的固定开销");
        e.put("note", "预期值 = 单元斜率 × " + unitCount
            + "；改用两点法前用单点（块数=k）会高估约 32%（把固定开销摊到 k 块上）。"
            + "跑一次查询后前端会换成实测值");
        return e;
    }

    /** 从 nativeDescribe 文本里取 levels（如 "levels=6"）。 */
    private static int levelsOf(long ctx) {
        String s = NativeBlindRotate.nativeDescribe(ctx);
        int i = s.indexOf("levels=");
        if (i < 0) {
            return -1;
        }
        i += "levels=".length();
        int j = i;
        while (j < s.length() && Character.isDigit(s.charAt(j))) {
            j++;
        }
        return j == i ? -1 : Integer.parseInt(s.substring(i, j));
    }

    /**
     * <b>CAPE Algorithm 2 的进程内端到端自检</b>（规划书 P0-1 ~ P0-4，逐条断言 + 负对照）。
     *
     * <p><b>为什么必须在进程内</b>（与 {@link #selftestSealed} 同一条理由）：
     * {@code Sealed} 查询里的 {@code β = ⟨a,s_L⟩ + r_a} 要求 {@code s_L} 是
     * <b>累加器所加密的那个秘密</b>的比特，而取它的 {@code nativeSecretBits} 需要
     * 进程内上下文句柄；另外 A2 的 {@code ct_score} 也需要"判定方持有同一把打分 sk"。
     * 所以跨进程只能验数据流（{@code CapeDefaultPathTest}），正确性断言落在这一支。
     *
     * <p>用 {@code -Dcape.selftest=true} 启动即跑。
     */
    private void selftestCape() {
        System.out.println();
        System.out.println("=== CAPE Algorithm 2 进程内端到端自检（P0-1 ~ P0-4）===");
        if (scorer == null) {
            System.out.println("  [skip] 打分信道未建（-Dcape.nocape=true）");
            return;
        }
        if (db.pool.isEmpty()) {
            System.out.println("  [FAIL] 池子为空");
            return;
        }
        int pass = 0;
        int fail = 0;

        CapeDemoData.PoolEntry pe = db.pool.get(0);
        List<String> query = Arrays.asList(pe.kws[0], pe.kws[1]);
        System.out.println("  查询（来自公开池子）: " + query);

        // ---- 客户端 QUERY（A2 QUERY 2-3）----
        com.fusepir.common.BfGen bf = com.fusepir.common.BfGen.choose(
            db.intMeta("maxSetSize", 4), epsFromMeta(), n);
        boolean[] bQry = bf.bits(query.subList(1, query.size()));
        long tau = 0;
        tau = BfGen.hammingWeight(bQry);
        long[] qbfWire = BloomChannel.encryptQueryWire(scorer, bQry);
        System.out.printf("  τ=%d（只在客户端）；q_BF 密文 %d 字节%n", tau, qbfWire.length);

        // ---- 服务器 ANSWER：default path 的那条入口，收字节 ----
        // ⚠️ 2026-10-14 晚：**必须带上锚查询**（anchorColIdx/anchorRowIdx）。
        //    以前这里不带，服务端就默认读关键词 #0 —— 而演示池第 0 组恰好以关键词 0 为锚，
        //    所以这段自检的绿灯是"巧合"换来的，不是协议能力。现在由客户端算出真锚。
        Map<String, Object> req = new LinkedHashMap<>();
        req.put("qBFBytes", qbfWire);
        CapeQuery.Sealed anchorQ = CapeQuery.buildIndicesOnly(
            n, K, R, tb.maxValues, db.keywords, query);
        req.put("anchorColIdx", anchorQ.colIdx);
        req.put("anchorRowIdx", anchorQ.rowIdx);
        System.out.println("  锚位置（由公开哈希 H 算出，**不是**写死的关键词 0）: col="
            + Arrays.toString(anchorQ.colIdx) + " row=" + Arrays.toString(anchorQ.rowIdx));
        long t0 = System.nanoTime();
        String res = runQueryCapeSealed(req);
        long queryMs = (System.nanoTime() - t0) / 1_000_000;
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) new CapeDemoData.JsonParser(res).parse().v;
        if (!Boolean.TRUE.equals(resp.get("ok"))) {
            System.out.println("  [FAIL] 服务器返回: " + resp.get("error"));
            return;
        }
        System.out.printf("  [ok] ANSWER %.1f s（含锚检索 + 打分）%n", queryMs / 1000.0);

        // ---- 客户端 DECODE（A2 DECODE 3-4 与 8-9）----
        long fGot = ((Number) resp.get("fingerprint")).longValue();
        @SuppressWarnings("unchecked")
        List<Object> cands = (List<Object>) resp.get("candidates");
        List<Integer> valueIds = new ArrayList<>();
        List<long[]> ctScores = new ArrayList<>();
        for (Object o : cands) {
            @SuppressWarnings("unchecked")
            Map<String, Object> one = (Map<String, Object>) o;
            @SuppressWarnings("unchecked")
            List<Object> bytes = (List<Object>) one.get("ctScoreBytes");
            long[] w = new long[bytes.size()];
            for (int i = 0; i < w.length; i++) {
                w[i] = ((Number) bytes.get(i)).longValue();
            }
            ctScores.add(w);
        }
        // 候选值由客户端从 ctPay 自己解（服务器不再发 id）—— 论文 §4.1 的要求。
        valueIds.addAll(CapeDecode.decodePayload(resp));
        // ⚠️ 此前是 `CapeDemoData.inField(kw.hashCode(), t)` —— 那是**旧的 32-bit 指纹**。
        // 40-bit 上线后它必然对不上载荷里的指纹 ⇒ P0-4 恒 FAIL。
        // 现在走 bff 层的唯一实现（A1 SETUP 1 的 fp）。
        long fpWant = com.fusepir.bff.BffSetup.fp(query.get(0));

        int[] counts = {0, 0};
        CapeDecode.DecodeResult dr = decodeWire(valueIds, ctScores, fpWant, fGot, tau,
            counts);
        report(counts, "P0-4 指纹校验（f == fp(K)）", dr.fingerprintOk, "f=" + fGot);
        report(counts, "P0-3 判定只读 Dec(ct_score)，且至少接受一条",
            !dr.accepted.isEmpty(), "接受=" + dr.accepted);

        // 明文真值：各关键词值集合的交集（客户端本地就能算）
        List<Integer> want = new ArrayList<>(db.kwToMovies.get(query.get(0)));
        for (int i = 1; i < query.size(); i++) {
            want.retainAll(db.kwToMovies.get(query.get(i)));
        }
        java.util.Collections.sort(want);
        if (want.size() > tb.maxValues) {
            want = new ArrayList<>(want.subList(0, tb.maxValues));
        }
        System.out.println("      明文真值（K 交集）= " + want + "；密文判定接受 = " + dr.accepted);
        report(counts, "接受的候选与明文真值完全一致",
            !want.isEmpty() && new java.util.TreeSet<>(want)
                .equals(new java.util.TreeSet<>(dr.accepted)),
            "accepted=" + dr.accepted + " want=" + want);

        // ---- P0-2：每候选一组 ----
        report(counts, "P0-2 每候选各带自己的 ct_score 字节",
            !valueIds.isEmpty() && ctScores.size() == valueIds.size(),
            "候选=" + valueIds);
        report(counts, "响应里不含任何明文分数", !responseHasPlainScore(resp), "");
        for (int j = 0; j < dr.scores.size(); j++) {
            System.out.printf("      候选 v=%d : Dec(ct_score)=%d  %s%n", valueIds.get(j),
                dr.scores.get(j), dr.scores.get(j) == tau ? "== τ ⇒ 接受" : "< τ ⇒ 拒绝");
        }

        // ---- 负对照 ----
        // N1：把过线后的 ctScoreBytes 置零 ⇒ 判定必须一条都不接受（验收定义第 2 条）
        List<long[]> broken = new ArrayList<>();
        for (long[] w : ctScores) {
            long[] b2 = w.clone();
            Arrays.fill(b2, 0L);
            broken.add(b2);
        }
        CapeDecode.DecodeResult d1 = decodeWire(valueIds, broken, fpWant, fGot, tau,
            new int[2]);
        report(counts, "N1 把 ct_score 字节置零 ⇒ 判定一条都不接受", d1.accepted.isEmpty(),
            "接受=" + d1.accepted);

        // N2：指纹用错 ⇒ ⊥
        CapeDecode.DecodeResult d2 = decodeWire(valueIds, ctScores, fpWant + 1, fGot, tau,
            new int[2]);
        report(counts, "N2 指纹故意用错 ⇒ 返回 ⊥、不给任何值",
            !d2.fingerprintOk && d2.accepted.isEmpty(), d2.verdict);

        // N3：τ 改错 ⇒ 接受集合变
        CapeDecode.DecodeResult d3 = decodeWire(valueIds, ctScores, fpWant, fGot, tau + 1,
            new int[2]);
        report(counts, "N3 把 τ 改错 ⇒ 接受集合必须变",
            !d3.accepted.equals(dr.accepted), "τ=" + tau + " -> " + dr.accepted
                + "；τ+1 -> " + d3.accepted);

        // N5：坐标可还原（本轮新发现，未修）
        StringBuilder sb = new StringBuilder();
        CapeQuery.Sealed demo = CapeQuery.build(ctxHandle, n, K, R, tb.maxValues,
            tb.lBf, db.intMeta("maxSetSize", 4), epsFromMeta(), bootstrapBits(), db.keywords, query);
        boolean leakedCoord = CapeAlgorithm2Diag.demonstrateCoordinateRecovery(demo, 2L * n, sb);
        report(counts, "N5 服务器能从 (a, beta, sBits) 还原 r_a（⇒ 该隐私断言不成立）",
            leakedCoord, "见 docs/缺陷总表.md 的 D13 / P1-1");

        System.out.printf("  === %d PASS / %d FAIL ===%n", counts[0], counts[1]);
    }

    private static void report(int[] counts, String what, boolean ok, String detail) {
        System.out.printf("  [%s] %s%s%n", ok ? "PASS" : "FAIL", what,
            detail == null || detail.isEmpty() ? "" : "  —— " + detail);
        counts[ok ? 0 : 1]++;
    }

    /**
     * 进程内 DECODE：从**字节** load 密文，再逐条解密。
     *
     * <p>走字节而不是进程内对象，是为了让"客户端解的就是服务器发回来的那条密文"
     * 这件事在正确的性断言里也成立（负对照 N1 是在字节上破坏的）。
     */
    private CapeDecode.DecodeResult decodeWire(List<Integer> valueIds, List<long[]> wire,
                                                       long fpWant, long fGot, long tau,
                                                       int[] counts) {
        return CapeDecode.decodeWire(scorer, wire, valueIds, fpWant, fGot, tau, 0);
    }

    /** P1-3：把 {@code d} 的语义实测出来并打成报告（{@code -Dcape.selftest=true} 时随启动跑）。 */
    private void printDSemantics() {
        System.out.println();
        System.out.println("=== P1-3：d 的语义对齐（实测）===");
        CapeDSemanticsProbe.Report rep = CapeDSemanticsProbe.run(ctxHandle, n, d);
        for (String s : rep.lines) {
            System.out.println(s);
        }
        System.out.printf("  === %d PASS / %d FAIL ===%n", rep.pass, rep.fail);
    }

    /** 响应里有没有"看起来像明文分数"的字段。 */
    private static boolean responseHasPlainScore(Map<String, Object> resp) {        for (String k : resp.keySet()) {
            String lk = k.toLowerCase();
            if (lk.contains("score") && !lk.contains("ctscore") && !lk.contains("scorechannel")) {
                if (resp.get(k) instanceof Number) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * <b>合规路径（sealed）的进程内自检</b> —— 正确性断言唯一有效的落点。
     *
     * <p>为什么必须在进程内：{@code β = ⟨a,s_L⟩ + r_a} 里的 {@code s_L} 必须是
     * **累加器所加密的那个秘密**的比特，而取它的 {@code nativeSecretBits} 需要
     * **进程内的上下文句柄**（裸指针）。跨进程传会段错误、新建上下文会拿到另一个
     * 随机秘密（载荷恒为 0）—— 两种错法我都实测踩过。
     *
     * <p>验证内容：
     * <ol>
     *   <li>出站 JSON 不含关键词 / τ / b_qry；</li>
     *   <li>服务器 ANSWER 只收到密文（它本来就没有关键词）；</li>
     *   <li>客户端用**自己保留的** b_qry 与 τ 做论文 A2 DECODE 的判定，答案与
     *       「取池子里那个已验证组合的共同命中」一致。</li>
     * </ol>
     *
     * <p>用 {@code -Dcape.selftest=true} 启动即运行。
     */
    private void selftestSealed() {
        System.out.println();
        System.out.println("=== sealed 合规路径进程内自检 ===");
        int pass = 0;
        int fail = 0;

        // 取一个池内组合（池子是公开数据，不是隐私）
        if (db.pool.isEmpty()) {
            System.out.println("  [FAIL] 池子为空");
            return;
        }
        CapeDemoData.PoolEntry pe = db.pool.get(0);
        List<String> query = Arrays.asList(pe.kws[0], pe.kws[1]);
        System.out.println("  查询（**不进 JSON**）: " + query);
        CapeQuery.Sealed q = CapeQuery.build(ctxHandle, n, K, R, tb.maxValues,
            tb.lBf, db.intMeta("maxSetSize", 4), epsFromMeta(), bootstrapBits(), db.keywords, query,
            true /* P1-1: 列选择子以密文送出 */);
        String json = CapeQuery.toJson(q);

        // 1. 出站隐私
        boolean leaked = false;
        for (String kw : query) {
            if (json.contains(kw)) {
                leaked = true;
            }
        }
        System.out.println("  1. 出站 JSON " + json.length() + " 字符，不含关键词: "
            + (!leaked ? "PASS" : "FAIL"));
        pass += leaked ? 0 : 1;
        fail += leaked ? 1 : 0;

        // 1b. P1-1：列号本身也必须不在线路上（这才是这一轮买的东西）
        //     colSel 是密文流，colIdx 不该出现；两者互斥由 toJson 保证。
        boolean colLeak = json.contains("\"colIdx\"");
        boolean hasSel = json.contains("\"colSel\"");
        System.out.println("  1b. 线路里没有明文列号（发的是 colSel 密文流）: "
            + ((!colLeak && hasSel) ? "PASS" : "FAIL")
            + "  [colIdx=" + colLeak + " colSel=" + hasSel + "]");
        pass += (!colLeak && hasSel) ? 1 : 0;
        fail += (!colLeak && hasSel) ? 0 : 1;

        // 2. 服务器 ANSWER（同一个 ctxHandle ⇒ β 与累加器同一个秘密）
        String res = runQuerySealed(q);
        @SuppressWarnings("unchecked")
        Map<String, Object> resp = (Map<String, Object>) new CapeDemoData.JsonParser(res).parse().v;
        boolean ok = Boolean.TRUE.equals(resp.get("ok"));
        System.out.println("  2. 服务器 ANSWER: " + (ok ? "ok" : ("失败 " + resp.get("error"))));
        if (!ok) {
            System.out.println("  === " + pass + " PASS / " + (fail + 1) + " FAIL ===");
            return;
        }
        pass++;
        @SuppressWarnings("unchecked")
        Map<String, Object> timing = (Map<String, Object>) resp.get("timing");
        System.out.printf("     QUERY %.3f ms / ANSWER %.1f ms / DECODE %.3f ms（单元 %s）%n",
            timing.get("queryMs"), timing.get("answerMs"), timing.get("decodeMs"),
            timing.get("unitCount"));

        // 3. 客户端 DECODE（论文 A2 L1075-1082）
        @SuppressWarnings("unchecked")
        List<Object> raw = (List<Object>) resp.get("payload");
        long[] payload = new long[raw.size()];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = ((Number) raw.get(i)).longValue();
        }
        int count = (int) payload[1];
        System.out.println("  3. 载荷 valueCount=" + count + " τ=" + q.tau
            + " 前 3 项=[" + payload[0] + ", " + payload[1] + ", " + payload[2] + "]");
        List<Integer> accepted = new ArrayList<>();
        for (int j = 0; j < tb.maxValues && j < count; j++) {
            int off = 2 + j * (1 + tb.lBf);
            int valueId = (int) payload[off];
            if (valueId <= 0) {
                continue;
            }
            long s = 0;
            for (int bi = 0; bi < tb.lBf; bi++) {
                if (q.bQry[bi] && payload[off + 1 + bi] != 0) {
                    s++;
                }
            }
            if (s == q.tau) {
                accepted.add(valueId);
            }
        }
        List<Integer> want = pe.movies;
        System.out.println("     接受=" + accepted + "　池内真值=" + want);
        boolean match = !accepted.isEmpty() && want.containsAll(accepted);
        System.out.println("  4. 答案与池内真值一致: " + (match ? "PASS" : "FAIL"));
        // ⚠️ 原来这里写的是 `pass += match ? 1 : 0; fail += match ? 1 : 0;` ——
        //    两项都加，于是打印永远是 "N PASS / N FAIL"，与逐条断言矛盾。
        //    这类"计数器自己错了"的 bug 比断言失败更隐蔽：它让整段输出不可信。
        pass += match ? 1 : 0;
        fail += match ? 0 : 1;

        System.out.println("  === " + pass + " PASS / " + fail + " FAIL ===");
    }

    /**
     * 引导密钥 {@code bsk = {RGSW(s_i)}} 所对应的比特，取自**本上下文**的秘密密钥。
     *
     * <p>这是 {@code blind_rotate} 那条不变量的落点：{@code β = Σ a_i·s_i + r_a} 里的
     * {@code s_i} 必须与建 {@code bk} 用的完全相同，否则净旋转量变成
     * {@code Σa_i(s_i^server − s_i^client) − r} ⇒ 载荷恒 0。
     *
     * <p>注意 {@code nativeSecretBits} 给的是「系数 == 1 或 0」的指示函数
     * （三元秘密的 −1 被归零），所以它**只能**用来生成 bk 的比特，
     * 不能当作真秘密的多项式系数 —— 这一点在 `CapeQuery` 的注释里有完整说明。
     */
    private int[] bootstrapBits() {
        Long[] b = NativeBlindRotate.nativeSecretBits(ctxHandle, d);
        int[] bits = new int[d];
        for (int i = 0; i < d && i < b.length; i++) {
            bits[i] = b[i].intValue();
        }
        return bits;
    }

    /** 与 {@code CapeDemoData.epsFromMeta} 同源，供自检构造客户端查询用。 */
    private double epsFromMeta() {
        Object v = db.meta.get("epsBf");
        return v instanceof Number ? ((Number) v).doubleValue() : Math.pow(2, -6);
    }

    /** Curated keyword pairs that are known to return a non-empty answer. */
    private void hPool(HttpExchange ex) throws IOException {        List<Object> out = new ArrayList<>();
        for (CapeDemoData.PoolEntry e : db.pool) {
            Map<String, Object> one = new LinkedHashMap<>();
            one.put("kws", Arrays.asList(e.kws));
            one.put("count", e.movies.size());
            out.add(one);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("total", out.size());
        m.put("pool", out);
        send(ex, 200, Json.write(m));
    }

    /**
     * <b>{@code /api/query}</b>：两个入口合一，按请求体分发。
     *
     * <table border="1">
     *   <tr><th>请求体</th><th>走哪条</th><th>判定</th></tr>
     *   <tr><td>含 <b>{@code qBFBytes}</b>（{@code q_BF} 的密文字节）</td>
     *       <td><b>CAPE Algorithm 2 默认路径</b>（2026-10-14 起）</td>
     *       <td>客户端 <b>{@code Dec(ct_score) == τ}</b> + 指纹 ⊥</td></tr>
     *   <tr><td>含 {@code keywords}（明文关键词）</td>
     *       <td>老演示路径（保留，不打断已提交的前端）</td>
     *       <td>明文合取 {@code boolean conj} —— <b>不是论文的 CAPE 判定</b></td></tr>
     * </table>
     *
     * <p>分发而不是替换，是刻意的：老路径的明文合取是**已记录的偏差**，
     * 一夜之间换掉会让前端与老探针一起哑掉；但正式路径从今天起是密文那一条，
     * 这件事写在这里、也写在 {@code /api/state} 的 {@code defaultPath} 字段里。
     */
    private void hQuery(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, err("POST only"));
            return;
        }
        String body = read(ex);
        @SuppressWarnings("unchecked")
        Map<String, Object> req = (Map<String, Object>) new CapeDemoData.JsonParser(body)
            .parse().v;

        boolean capePath = req.containsKey("qBFBytes");
        Object kwsObj = req.get("keywords");
        List<String> kws = new ArrayList<>();
        if (kwsObj instanceof List) {
            for (Object o : (List<?>) kwsObj) {
                kws.add(String.valueOf(o));
            }
        }
        if (!capePath && kws.isEmpty()) {
            send(ex, 200, err("请求体既没有 qBFBytes（CAPE 默认路径）也没有 keywords（老路径）"));
            return;
        }
        if (!busy.compareAndSet(false, true)) {
            send(ex, 200, err("a query is already running"));
            return;
        }
        // ⚠️ CAPE 路径下服务器**不知道**任何关键词，所以日志里也打不出来
        currentKws = capePath ? "(cape: 收到 q_BF 密文，关键词未送达)"
            : String.join(" + ", kws);
        try {
            String res = capePath ? runQueryCapeSealed(req) : runQueryLegacy(kws);
            lastResult.set(res);
            send(ex, 200, res);
        } finally {
            busy.set(false);
            currentKws = "";
        }
    }

    /**
     * <b>合规路径</b>：接受客户端构造好的**密文查询**，服务器全程不接触明文关键词。
     *
     * <p>这是逐子程序核对 <b>D1</b> 的修复落点。请求体即
     * {@link CapeQuery#toJson} 的输出：{@code {colIdx,rowIdx,a,beta,sBits,bf}}，
     * 里面**没有关键词、没有 τ、没有 b_qry**。
     *
     * <p>`/api/query`（收明文关键词）保留只是为了不打断已经写好并提交的前端；
     * 它内部走的也是同一条 sealed 执行路径（先在本地把查询封起来），
     * **服务器侧的 ANSWER 只有一个实现，就是 {@link #runQuerySealed}**。
     */
    private void hQuerySealed(HttpExchange ex) throws IOException {
        // ⚠️ 这道闸门的历史要留着，因为它是一次真实的教训。
        //
        //   2026-10-14 之前，这条路径的载荷**恒为 0**（根因是 sBits 的
        //   int[]/jlongArray JNI 类型不匹配 —— 见 cape_answer_core 里那段注释），
        //   于是当时的处理是「默认 501 拒绝」，理由是：
        //   **一个「返回成功但结果是 0」的接口比一个报错的接口危险得多。**
        //   那个判断是对的，只是它遮住的是根因、不是症状。
        //
        //   现在根因已修，且进程内验收（-Dcape.selftest=true 的 P1-1 段）给出了
        //   「逐系数一致 + 两条负对照」的证据，所以闸门翻转为**默认放行**，
        //   只保留 -Dcape.sealed=false 作为显式关闭（这条路径现在要过一次
        //   41 MB 的选择子流，内存吃紧的机器需要能单独关掉它）。
        if ("false".equalsIgnoreCase(System.getProperty("cape.sealed"))) {
            send(ex, 501, err("sealed 路径被 -Dcape.sealed=false 显式关闭"));
            return;
        }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, err("POST only"));
            return;
        }
        String body = read(ex);
        CapeQuery.Sealed q;
        try {
            q = parseSealed(body);
        } catch (Exception e) {
            send(ex, 200, err("bad sealed query: " + e));
            return;
        }
        if (!busy.compareAndSet(false, true)) {
            send(ex, 200, err("a query is already running"));
            return;
        }
        // 日志只打收到的位置，**不打任何关键词** —— 服务器根本没有它们
        currentKws = "(sealed: col=" + java.util.Arrays.toString(q.colIdx) + ")";
        try {
            String res = runQuerySealed(q);
            lastResult.set(res);
            send(ex, 200, res);
        } finally {
            busy.set(false);
            currentKws = "";
        }
    }

    /**
     * <b>{@code /api/query-cape}</b> 的 HTTP 入口。
     *
     * <p>请求体：{@code {"d2PlaintextBf": [0/1 × l_BF]}}。
     */
    /**
     * <b>{@code /api/selftest/column}</b>：P1-1 的进程内验收。
     *
     * <p>P1-1 = 把列选择子按论文 A1 QUERY 4-5 做成**客户端密文** {@code q^col_a}，
     * 服务器不再拿到明文 {@code c_a}（D13 的前半句）。
     *
     * <h3>为什么这个入口必须是进程内的</h3>
     * 选择子密文流实测 <b>41 MB</b>（N=8192、C=26、k=3，每条约 524 KB），
     * 走 JSON 要编成上亿个数字。真实验收只关心「同样的选择子语义下，
     * 载荷是否逐系数一致」，所以这里直接把 {@code byte[]} 放进 Map，不过 JSON。
     * 过 JSON 的那条路仍然存在（{@code toJson} 的 {@code colSel}，7 字节/long 打包），
     * 由 {@code CapeSealedFlowTest} 覆盖格式，不在这里重复。
     *
     * <h3>断言与负对照（缺一不可）</h3>
     * <ol>
     *   <li><b>正</b>：密文选择子路径的载荷 == 明文列号（基线）路径的载荷，逐系数；</li>
     *   <li><b>负</b>：换一个**别的列**的 one-hot ⇒ 载荷必须不同（否则断言是空的）；</li>
     *   <li><b>负</b>：全零选择子 ⇒ 载荷必须全零（否则选择子根本没起作用）。</li>
     * </ol>
     * 第 2 条的正对照就是第 1 条：不同列必须给出不同载荷，而正确列必须给出与基线
     * 相同的载荷 —— 两条一起才排除"载荷恒 0"和"载荷与选择子无关"。
     *
     * <p>默认关闭（只认 {@code -Dcape.selftest=true}）：一次要跑 4 遍完整 ANSWER。
     */
    private void hColumnSelftest(HttpExchange ex) throws IOException {
        if (!Boolean.getBoolean("cape.selftest")) {
            send(ex, 403, err("进程内自检入口默认关闭；服务端加 -Dcape.selftest=true 才开放"));
            return;
        }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, err("POST only"));
            return;
        }
        if (!busy.compareAndSet(false, true)) {
            send(ex, 200, err("a query is already running"));
            return;
        }
        try {
            send(ex, 200, selftestColumnSelectors());
        } finally {
            busy.set(false);
            currentKws = "";
        }
    }

    /**
     * P1-1 验收本体。返回一份 JSON 报告（{@code ok} 为真表示三条断言全过）。
     *
     * <p>被 {@code /api/selftest/column} 与启动期 {@code -Dcape.selftest=true} 共用，
     * 所以它是 static 无法做到的 —— 它要读服务实例的 {@code ctxHandle} 与表。
     */
    private String selftestColumnSelectors() {
        List<String> lines = new ArrayList<>();
        int pass = 0;
        int fail = 0;
        if (db.pool.isEmpty()) {
            return err("池子为空");
        }
        CapeDemoData.PoolEntry pe = db.pool.get(0);
        List<String> query = Arrays.asList(pe.kws[0], pe.kws[1]);
        lines.add("查询（**不进 JSON**）: " + query);

        // 基线与 P1-1 用**同一次** build 出来的 colIdx，保证"同样的选择子语义"。
        CapeQuery.Sealed base = CapeQuery.build(ctxHandle, n, K, R, tb.maxValues,
            tb.lBf, db.intMeta("maxSetSize", 4), epsFromMeta(), bootstrapBits(), db.keywords, query);
        int C = tb.c;
        long t0 = System.nanoTime();

        // ---------- 1. 基线（明文列号）----------
        long[] payBase = NativeBlindRotate.nativeCapeAnswerSealed(ctxHandle, d, C, K, tb.bPay,
            tableFlat, base.colIdx, base.rowIdx, base.a, base.beta, base.sBits);
        long baseMs = (System.nanoTime() - t0) / 1_000_000;
        lines.add("1. 基线（服务器按明文列号自造 one-hot）载荷: "
            + Arrays.toString(Arrays.copyOf(payBase, Math.min(4, payBase.length))) + " ...");
        lines.add("   基线 colIdx（服务器看得到）: " + Arrays.toString(base.colIdx));

        // ---------- 2. P1-1（客户端密文选择子）----------
        long t1 = System.nanoTime();
        byte[] blob = CapeQuery.encryptColumnSelectors(ctxHandle, K, C, base.colIdx);
        long encMs = (System.nanoTime() - t1) / 1_000_000;
        long[] payC = NativeBlindRotate.nativeCapeAnswerSealedC(ctxHandle, d, C, K, tb.bPay,
            tableFlat, blob, base.a, base.beta, base.sBits);
        long capeMs = (System.nanoTime() - t1) / 1_000_000 - encMs;

        boolean same = Arrays.equals(payBase, payC);
        if (same) {
            pass++;
        } else {
            fail++;
        }
        lines.add("2. P1-1（客户端密文选择子）载荷: "
            + Arrays.toString(Arrays.copyOf(payC, Math.min(4, payC.length))) + " ...");
        lines.add("   [断言 1] 与基线逐系数一致: " + (same ? "PASS" : "FAIL"));
        lines.add("   选择子流 " + blob.length + " 字节（k=" + K + " × C=" + C
            + " 条，每条 " + (K * C > 0 ? (blob.length - 4L * K * C) / (K * C) : 0)
            + " 字节），加密 " + encMs + " ms，ANSWER " + capeMs + " ms"
            + "（基线 " + baseMs + " ms）");
        lines.add("   ⚠️ 41 MB 量级的通信代价是「C 条独立密文」这条读法的直接后果，"
            + "不是本实现的浪费：q_BF 只有 " + (tb.lBf > 0 ? "211 KB" : "?") + " 量级。");

        // ---------- 3. 负对照 a：换一个别的列 ----------
        long[] wrong = base.colIdx.clone();
        wrong[0] = (wrong[0] + 1) % C;
        byte[] blobWrong = CapeQuery.encryptColumnSelectors(ctxHandle, K, C, wrong);
        long[] payWrong = NativeBlindRotate.nativeCapeAnswerSealedC(ctxHandle, d, C, K, tb.bPay,
            tableFlat, blobWrong, base.a, base.beta, base.sBits);
        boolean differs = !Arrays.equals(payBase, payWrong);
        if (differs) {
            pass++;
        } else {
            fail++;
        }
        lines.add("3. [负对照] 第 0 路换列 " + base.colIdx[0] + " -> " + wrong[0]
            + "，载荷必须不同: " + (differs ? "PASS" : "FAIL")
            + "（前 4 项 " + Arrays.toString(Arrays.copyOf(payWrong, Math.min(4, payWrong.length))) + "）");

        // ---------- 4. 负对照 b：全零选择子 ----------
        long[] eZero = new long[K * C];
        byte[] blobZero = CapeQuery.encryptSelectorVector(ctxHandle, eZero);
        long[] payZero = NativeBlindRotate.nativeCapeAnswerSealedC(ctxHandle, d, C, K, tb.bPay,
            tableFlat, blobZero, base.a, base.beta, base.sBits);
        boolean allZero = true;
        for (long v : payZero) {
            if (v != 0) {
                allZero = false;
                break;
            }
        }
        if (allZero) {
            pass++;
        } else {
            fail++;
        }
        lines.add("4. [负对照] 全零选择子 ⇒ 载荷必须全零: " + (allZero ? "PASS" : "FAIL")
            + "（前 4 项 " + Arrays.toString(Arrays.copyOf(payZero, Math.min(4, payZero.length))) + "）");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("ok", fail == 0);
        out.put("pass", pass);
        out.put("fail", fail);
        out.put("columnSelectorBytes", blob.length);
        out.put("selPerQuery", K * C);
        out.put("tileBytes", K * C > 0 ? (blob.length - 4L * K * C) / (K * C) : 0);
        out.put("lines", lines);
        return Json.write(out);
    }

    /**
     * <b>{@code /api/selftest/ntt-share}</b>：P2-1 第一步 —— 量每列成本。
     *
     * <p>默认关闭（只认 {@code -Dcape.selftest=true}）：它要跑几十次真查询。
     */
    private void hNttShare(HttpExchange ex) throws IOException {
        if (!Boolean.getBoolean("cape.selftest")) {
            send(ex, 403, err("进程内自检入口默认关闭；服务端加 -Dcape.selftest=true 才开放"));
            return;
        }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, err("POST only"));
            return;
        }
        if (!busy.compareAndSet(false, true)) {
            send(ex, 200, err("a query is already running"));
            return;
        }
        currentKws = "(selftest: P2-1 每列成本)";
        try {
            int bProbe = Integer.getInteger("cape.prof.bpay", 4);
            List<String> lines = CapeNttShareProbe.runInProcess(
                ctxHandle, db, tb, tableFlat, n, K, d, bProbe);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", true);
            m.put("lines", lines);
            send(ex, 200, Json.write(m));
        } finally {
            busy.set(false);
            currentKws = "";
        }
    }

    private void hQueryCape(HttpExchange ex) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            send(ex, 405, err("POST only"));
            return;
        }
        String body = read(ex);
        Map<String, Object> req;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed =
                (Map<String, Object>) new CapeDemoData.JsonParser(body).parse().v;
            req = parsed;
        } catch (Exception e) {
            send(ex, 200, err("bad cape request: " + e));
            return;
        }
        if (!busy.compareAndSet(false, true)) {
            send(ex, 200, err("a query is already running"));
            return;
        }
        currentKws = "(cape: A2 ANSWER 4-8)";
        try {
            String res = runQueryCape(req);
            lastResult.set(res);
            send(ex, 200, res);
        } finally {
            busy.set(false);
            currentKws = "";
        }
    }

    /** 解析 {@link CapeQuery#toJson} 的输出。 */    @SuppressWarnings("unchecked")
    private static CapeQuery.Sealed parseSealed(String body) {
        Map<String, Object> req = (Map<String, Object>) new CapeDemoData.JsonParser(body).parse().v;
        CapeQuery.Sealed q = new CapeQuery.Sealed();
        // ---- P1-1：列信息的两种互斥形态 ----
        //   colSel 在  ⇒ 列选择子是密文（论文 A1 QUERY 5），**没有 colIdx**；
        //   colSel 不在 ⇒ 基线形式，服务器拿明文列号自己造 one-hot（D13 前半句）。
        if (req.containsKey("colSel")) {
            long[] packed = toLongs(req.get("colSel"));
            int byteLen = ((Number) req.get("colSelLen")).intValue();
            q.selBlob = ScorerWire.packedWireToBytes(packed, byteLen);
        }
        if (req.containsKey("colIdx")) {
            q.colIdx = toLongs(req.get("colIdx"));
        } else if (q.selBlob == null) {
            throw new IllegalArgumentException("sealed query 既没有 colSel 也没有 colIdx");
        }
        q.rowIdx = toLongs(req.get("rowIdx"));
        q.beta = toLongs(req.get("beta"));
        // `a` 由客户端扁平化 + 显式带 d（本项目的极简 JsonParser 不支持嵌套数组）
        long[] flat = toLongs(req.get("aFlat"));
        int d = ((Number) req.get("d")).intValue();
        int k = q.beta.length;
        if (d <= 0 || k <= 0 || flat.length < k * d) {
            throw new IllegalArgumentException("malformed aFlat: len=" + flat.length
                + " k=" + k + " d=" + d);
        }
        q.a = new long[k][d];
        for (int i = 0; i < k; i++) {
            System.arraycopy(flat, i * d, q.a[i], 0, d);
        }
        long[] sb = toLongs(req.get("sBits"));
        q.sBits = new int[sb.length];
        for (int i = 0; i < sb.length; i++) {
            q.sBits[i] = (int) sb[i];
        }
        if (q.colIdx == null) {
            // P1-1：服务器**没有**明文列号，只有一串不透明选择子密文。
            // 于是日志里也不该有列号 —— 这正是这条路要买的东西。
            q.colIdx = new long[0];
        }
        // 列信息必须二选一：要么 colIdx 有 k 项，要么 selBlob 非空。
        if (q.colIdx.length != k && q.selBlob == null) {
            throw new IllegalArgumentException("malformed sealed query: colIdx len="
                + q.colIdx.length + " k=" + k + " 且没有 colSel");
        }
        if (q.sBits.length < d) {
            throw new IllegalArgumentException("malformed sealed query: sBits 太短");
        }
        // bf 默认不外发（它是 b_qry 明文，能反解出查询关键词，见 toJson 注释）。
        // 字段名带 d2PlaintextBf 前缀就是为了让"这是明文、只用于 D2 开发"无法被误读。
        if (req.containsKey("d2PlaintextBf")) {
            q.bfSlots = toLongs(req.get("d2PlaintextBf"));
        }
        return q;
    }

    /**
     * 取一个整数数组，<b>两种形态都收</b>。
     *
     * <p>⚠️ 这个坑在本项目里出现过**三次**了（`qBFBytes` 一次、`anchorColIdx` 一次、
     * `d2PlaintextBf` 一次）：走 HTTP 时字段是 JSON 数组 ⇒ 解成 {@code List}；
     * 走**进程内**自检时是直接把 {@code long[]} 放进 Map ⇒ 类型是 {@code [J}。
     * 于是只判 {@code instanceof List} 的代码在跨进程测试里全绿，
     * 一到进程内自检就 {@code ClassCastException}。
     *
     * <p>⇒ 统一在这里收口，不再让每个调用点各写一遍判断。
     */
    private static long[] toLongs(Object o) {
        if (o instanceof long[]) {
            return (long[]) o;
        }
        if (o instanceof int[]) {
            int[] src = (int[]) o;
            long[] out = new long[src.length];
            for (int i = 0; i < src.length; i++) {
                out[i] = src[i];
            }
            return out;
        }
        List<?> l = (List<?>) o;
        long[] out = new long[l.size()];
        for (int i = 0; i < l.size(); i++) {
            out[i] = ((Number) l.get(i)).longValue();
        }
        return out;
    }

    private void hStatic(HttpExchange ex) throws IOException {        String p = ex.getRequestURI().getPath();
        if (p.equals("/") || p.isEmpty()) {
            p = "/index.html";
        }
        Path f = webRoot().resolve(p.substring(1)).normalize();
        if (!f.startsWith(webRoot()) || !Files.exists(f)) {
            send(ex, 404, "not found");
            return;
        }
        byte[] b = Files.readAllBytes(f);
        String ct = p.endsWith(".html") ? "text/html; charset=utf-8"
            : p.endsWith(".css") ? "text/css; charset=utf-8"
            : p.endsWith(".js") ? "application/javascript; charset=utf-8"
            : "application/octet-stream";
        ex.getResponseHeaders().set("Content-Type", ct);
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    /**
     * 页面根目录。
     *
     * <p><b>这里以前是坏的</b>：候选只有 {@code cape-demo/web} 和 1~2 级 {@code ..}，
     * 而 {@code run-mpc4j.ps1} 以 {@code coding\rgsw-lab} 为 CWD 跑 java ——
     * 到 {@code coding\cape-demo\web} 要爬 4 级（{@code ../../../../cape-demo/web}），
     * 于是三个候选全落空、{@code GET /} 返回 404：**服务正常但页面打不开**。
     * 同一个坑 {@link CapeDemoSetupProbe#resolveDb} 已经用「多级 .. 回溯」绕过了，
     * 这里补齐到 5 级，并支持 {@code -Dcape.web} 显式指定（启动脚本用它传绝对路径）。
     */
    private static Path webRoot() {
        String forced = System.getProperty("cape.web");
        if (forced != null && !forced.isEmpty()) {
            Path p = Paths.get(forced);
            if (Files.isDirectory(p)) {
                return p.toAbsolutePath().normalize();
            }
        }
        Path base = Paths.get("cape-demo", "web");
        Path[] cands = {
            base,
            Paths.get("..", "cape-demo", "web"),
            Paths.get("..", "..", "cape-demo", "web"),
            Paths.get("..", "..", "..", "cape-demo", "web"),
            Paths.get("..", "..", "..", "..", "cape-demo", "web"),
            Paths.get("..", "..", "..", "..", "..", "cape-demo", "web"),
        };
        for (Path c : cands) {
            if (Files.isDirectory(c)) {
                return c.toAbsolutePath().normalize();
            }
        }
        return base.toAbsolutePath().normalize();
    }

    private static String read(HttpExchange ex) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (InputStream in = ex.getRequestBody()) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) > 0) {
                bos.write(buf, 0, r);
            }
        }
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    // ------------------------------------------------------------------

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8756;
        int n = args.length > 1 ? Integer.parseInt(args[1]) : 8192;
        int d = args.length > 2 ? Integer.parseInt(args[2]) : 16;
        Path dbPath = CapeDemoSetupProbe.resolveDb(
            args.length > 3 ? args[3] : "cape-demo/db/keywords.json");

        System.out.println("=== CAPE native demo service ===");
        System.out.printf("[db] %s%n", dbPath);
        CapeDemoData db = CapeDemoData.load(dbPath);
        CapeDemoService svc = new CapeDemoService(port, n, d, db);

        // 三个进程内自检，都**默认关闭**，用 -Dcape.selftest=true 显式开启：
        //
        //   1. selftestCape()   —— **CAPE Algorithm 2 的正式路径**（P0-1 ~ P0-4 + 负对照）
        //   2. selftestSealed() —— /api/query-sealed 那条合规路径，现已是 P1-1 形态
        //      （列选择子以密文送出）
        //   3. selftestColumnSelectors() —— P1-1 的专属验收：密文选择子路径与明文列号
        //      基线逐系数一致 + 两条负对照。要跑 4 遍完整 ANSWER，所以也在这道开关后面。
        if (Boolean.getBoolean("cape.selftest")) {
            svc.selftestCape();
            svc.selftestSealed();
            svc.printDSemantics();
            System.out.println();
            System.out.println("=== P1-1：列选择子密文化（进程内验收）===");
            System.out.println(svc.selftestColumnSelectors());
        }

        svc.start();
        Thread.currentThread().join();      // serve until killed
    }
}
