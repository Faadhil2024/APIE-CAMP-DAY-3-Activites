import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  POLL_QUESTIONS,
  type AnswerChoice,
  type AnswersMap,
  type PublicLiveResults,
  type QuestionAggregate,
  type SessionPublicInfo,
  type StudentSelfState,
  type StudentStatus,
  type TaDashboardPayload,
  type TaQuestionBreakdown,
  type TaStudentRecord,
} from '../src/shared/questions.ts';

interface StoredStudent {
  id: string;
  sessionId: string;
  deviceId: string;
  tokenHash: string;
  name: string;
  status: StudentStatus;
  answers: AnswersMap;
  joinedAt: string;
  updatedAt: string;
  completedAt: string | null;
}

interface StoredSession {
  id: string;
  label: string;
  joinCode: string;
  createdAt: string;
  students: StoredStudent[];
}

interface DatabaseSchema {
  activeSession: StoredSession;
  archivedSessions: StoredSession[];
}

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'vibe-check-db.json');
const VALID_QUESTION_IDS = new Set(POLL_QUESTIONS.map((q) => q.id));

function generateJoinCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let suffix = '';
  for (let i = 0; i < 4; i++) {
    suffix += chars[crypto.randomInt(0, chars.length)];
  }
  return `VIBE-${suffix}`;
}

function createFreshSession(label?: string): StoredSession {
  const now = new Date().toISOString();
  return {
    id: `sess_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`,
    label: label && label.trim() ? label.trim().slice(0, 60) : `Class Session (${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' })})`,
    joinCode: generateJoinCode(),
    createdAt: now,
    students: [],
  };
}

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function tokensEqual(rawToken: string, expectedHash: string): boolean {
  const actualBuf = Buffer.from(hashToken(rawToken), 'hex');
  const expectedBuf = Buffer.from(expectedHash, 'hex');
  if (actualBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(actualBuf, expectedBuf);
}

class VibeCheckStore {
  private db: DatabaseSchema;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor() {
    this.db = this.loadFromDisk();
  }

  private ensureDataDir(): void {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
  }

  private loadFromDisk(): DatabaseSchema {
    this.ensureDataDir();
    if (fs.existsSync(DB_FILE)) {
      try {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        const parsed = JSON.parse(raw) as DatabaseSchema;
        if (parsed && parsed.activeSession && Array.isArray(parsed.activeSession.students)) {
          return {
            activeSession: parsed.activeSession,
            archivedSessions: Array.isArray(parsed.archivedSessions) ? parsed.archivedSessions : [],
          };
        }
      } catch (err) {
        console.error('Failed to read database file, initializing fresh store:', err);
      }
    }
    const initial: DatabaseSchema = {
      activeSession: createFreshSession('Live Classroom Session'),
      archivedSessions: [],
    };
    this.writeSync(initial);
    return initial;
  }

  private writeSync(data: DatabaseSchema): void {
    this.ensureDataDir();
    const tmpPath = `${DB_FILE}.${process.pid}.tmp`;
    fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmpPath, DB_FILE);
  }

  private persist(): Promise<void> {
    const snapshot = JSON.parse(JSON.stringify(this.db)) as DatabaseSchema;
    this.writeQueue = this.writeQueue.then(() => {
      this.writeSync(snapshot);
    });
    return this.writeQueue;
  }

  public getActiveSessionPublic(): SessionPublicInfo {
    const { id, label, joinCode, createdAt } = this.db.activeSession;
    return { id, label, joinCode, createdAt };
  }

  private toStudentSelf(student: StoredStudent): StudentSelfState {
    const answeredCount = Object.keys(student.answers).filter((k) => VALID_QUESTION_IDS.has(k)).length;
    return {
      id: student.id,
      sessionId: student.sessionId,
      name: student.name,
      status: student.status,
      answers: { ...student.answers },
      answeredCount,
      joinedAt: student.joinedAt,
      completedAt: student.completedAt,
    };
  }

  public async joinStudent(params: {
    name: string;
    deviceId: string;
    joinCode?: string;
    existingToken?: string;
  }): Promise<
    | { ok: true; student: StudentSelfState; studentToken: string; resumed: boolean }
    | { ok: false; status: number; code: string; error: string }
  > {
    const trimmedName = params.name.trim().replace(/\s+/g, ' ');
    if (trimmedName.length < 1 || trimmedName.length > 40) {
      return {
        ok: false,
        status: 400,
        code: 'INVALID_NAME',
        error: 'Please enter a display name between 1 and 40 characters.',
      };
    }

    const cleanDeviceId = params.deviceId.trim();
    if (!/^[a-zA-Z0-9_-]{8,128}$/.test(cleanDeviceId)) {
      return {
        ok: false,
        status: 400,
        code: 'INVALID_DEVICE',
        error: 'Invalid browser session identifier. Please reload and try again.',
      };
    }

    const session = this.db.activeSession;

    if (params.joinCode && params.joinCode.trim().length > 0) {
      if (params.joinCode.trim().toUpperCase() !== session.joinCode.toUpperCase()) {
        return {
          ok: false,
          status: 400,
          code: 'INVALID_JOIN_CODE',
          error: 'That join code does not match the active classroom session.',
        };
      }
    }

    const existing = session.students.find((s) => s.deviceId === cleanDeviceId);
    if (existing) {
      if (params.existingToken && tokensEqual(params.existingToken, existing.tokenHash)) {
        return {
          ok: true,
          student: this.toStudentSelf(existing),
          studentToken: params.existingToken,
          resumed: true,
        };
      }
      return {
        ok: false,
        status: 409,
        code: 'DUPLICATE_PARTICIPATION',
        error: `This device has already joined the active session as "${existing.name}". Duplicate submissions are disabled.`,
      };
    }

    const rawToken = crypto.randomBytes(24).toString('hex');
    const now = new Date().toISOString();
    const newStudent: StoredStudent = {
      id: `stu_${crypto.randomUUID().replace(/-/g, '').slice(0, 14)}`,
      sessionId: session.id,
      deviceId: cleanDeviceId,
      tokenHash: hashToken(rawToken),
      name: trimmedName,
      status: 'Joined',
      answers: {},
      joinedAt: now,
      updatedAt: now,
      completedAt: null,
    };

    session.students.push(newStudent);
    await this.persist();

    return {
      ok: true,
      student: this.toStudentSelf(newStudent),
      studentToken: rawToken,
      resumed: false,
    };
  }

  public getStudentSelf(studentId: string, studentToken: string): StudentSelfState | null {
    const student = this.db.activeSession.students.find((s) => s.id === studentId);
    if (!student) return null;
    if (!tokensEqual(studentToken, student.tokenHash)) return null;
    return this.toStudentSelf(student);
  }

  public async saveAnswer(params: {
    studentId: string;
    studentToken: string;
    questionId: string;
    choice: AnswerChoice;
  }): Promise<
    | { ok: true; student: StudentSelfState }
    | { ok: false; status: number; error: string }
  > {
    if (!VALID_QUESTION_IDS.has(params.questionId)) {
      return { ok: false, status: 400, error: 'Unknown question identifier.' };
    }
    if (params.choice !== 'A' && params.choice !== 'B') {
      return { ok: false, status: 400, error: 'Invalid answer choice.' };
    }

    const student = this.db.activeSession.students.find((s) => s.id === params.studentId);
    if (!student || !tokensEqual(params.studentToken, student.tokenHash)) {
      return { ok: false, status: 401, error: 'Session verification failed. Please rejoin the active poll.' };
    }

    if (student.status === 'Completed') {
      return { ok: false, status: 400, error: 'Responses are locked after submission.' };
    }

    student.answers[params.questionId] = params.choice;
    student.status = 'In Progress';
    student.updatedAt = new Date().toISOString();

    await this.persist();
    return { ok: true, student: this.toStudentSelf(student) };
  }

  public async completeStudent(params: {
    studentId: string;
    studentToken: string;
  }): Promise<
    | { ok: true; student: StudentSelfState; newlyCompleted: boolean }
    | { ok: false; status: number; error: string }
  > {
    const student = this.db.activeSession.students.find((s) => s.id === params.studentId);
    if (!student || !tokensEqual(params.studentToken, student.tokenHash)) {
      return { ok: false, status: 401, error: 'Session verification failed. Please rejoin the active poll.' };
    }

    if (student.status === 'Completed') {
      return { ok: true, student: this.toStudentSelf(student), newlyCompleted: false };
    }

    const missing = POLL_QUESTIONS.filter(
      (q) => student.answers[q.id] !== 'A' && student.answers[q.id] !== 'B'
    );

    if (missing.length > 0) {
      return {
        ok: false,
        status: 400,
        error: `Please answer all 10 questions before submitting (missing ${missing.map((m) => `Q${m.number}`).join(', ')}).`,
      };
    }

    const now = new Date().toISOString();
    student.status = 'Completed';
    student.completedAt = now;
    student.updatedAt = now;

    await this.persist();
    return { ok: true, student: this.toStudentSelf(student), newlyCompleted: true };
  }

  public getPublicLiveResults(): PublicLiveResults {
    const session = this.db.activeSession;
    const totalJoined = session.students.length;
    const completedStudents = session.students.filter((s) => s.status === 'Completed');
    const completedCount = completedStudents.length;
    const stillAnsweringCount = totalJoined - completedCount;

    const questions: QuestionAggregate[] = POLL_QUESTIONS.map((q) => {
      let countA = 0;
      let countB = 0;
      for (const s of completedStudents) {
        if (s.answers[q.id] === 'A') countA++;
        else if (s.answers[q.id] === 'B') countB++;
      }
      const totalVotes = countA + countB;
      const percentA = totalVotes > 0 ? Math.round((countA / totalVotes) * 100) : 0;
      const percentB = totalVotes > 0 ? 100 - percentA : 0;
      return {
        questionId: q.id,
        totalVotes,
        countA,
        countB,
        percentA,
        percentB,
      };
    });

    return {
      session: this.getActiveSessionPublic(),
      totalJoined,
      completedCount,
      stillAnsweringCount,
      questions,
      updatedAt: new Date().toISOString(),
    };
  }

  public getTaDashboardPayload(): TaDashboardPayload {
    const session = this.db.activeSession;
    const totalJoined = session.students.length;
    const completedCount = session.students.filter((s) => s.status === 'Completed').length;
    const inProgressCount = session.students.filter((s) => s.status === 'In Progress').length;
    const joinedOnlyCount = session.students.filter((s) => s.status === 'Joined').length;
    const stillAnsweringCount = totalJoined - completedCount;
    const completionRate = totalJoined > 0 ? Math.round((completedCount / totalJoined) * 100) : 0;

    const students: TaStudentRecord[] = [...session.students]
      .sort((a, b) => new Date(b.joinedAt).getTime() - new Date(a.joinedAt).getTime())
      .map((s) => ({
        id: s.id,
        name: s.name,
        status: s.status,
        answers: { ...s.answers },
        answeredCount: Object.keys(s.answers).filter((k) => VALID_QUESTION_IDS.has(k)).length,
        joinedAt: s.joinedAt,
        updatedAt: s.updatedAt,
        completedAt: s.completedAt,
      }));

    const questionBreakdowns: TaQuestionBreakdown[] = POLL_QUESTIONS.map((q) => {
      const studentsA: string[] = [];
      const studentsB: string[] = [];

      for (const s of session.students) {
        const choice = s.answers[q.id];
        if (choice === 'A') studentsA.push(s.name);
        else if (choice === 'B') studentsB.push(s.name);
      }

      const countA = studentsA.length;
      const countB = studentsB.length;
      const totalAnswered = countA + countB;
      const percentA = totalAnswered > 0 ? Math.round((countA / totalAnswered) * 100) : 0;
      const percentB = totalAnswered > 0 ? 100 - percentA : 0;

      return {
        questionId: q.id,
        totalAnswered,
        countA,
        countB,
        percentA,
        percentB,
        studentsA,
        studentsB,
      };
    });

    return {
      session: this.getActiveSessionPublic(),
      stats: {
        totalJoined,
        completedCount,
        inProgressCount,
        joinedOnlyCount,
        stillAnsweringCount,
        completionRate,
      },
      students,
      questionBreakdowns,
      updatedAt: new Date().toISOString(),
    };
  }

  public getTaStudentById(studentId: string): TaStudentRecord | null {
    const s = this.db.activeSession.students.find((item) => item.id === studentId);
    if (!s) return null;
    return {
      id: s.id,
      name: s.name,
      status: s.status,
      answers: { ...s.answers },
      answeredCount: Object.keys(s.answers).filter((k) => VALID_QUESTION_IDS.has(k)).length,
      joinedAt: s.joinedAt,
      updatedAt: s.updatedAt,
      completedAt: s.completedAt,
    };
  }

  public buildCsvExport(): string {
    const headers = [
      'Student Name',
      'Status',
      'Progress',
      'Joined At',
      'Completed At',
      ...POLL_QUESTIONS.map((q) => `Q${q.number}: ${q.prompt}`),
    ];

    const escapeCsv = (value: string): string => {
      const safe = value.replace(/"/g, '""');
      return `"${safe}"`;
    };

    const rows = this.db.activeSession.students.map((s) => {
      const answeredCount = Object.keys(s.answers).filter((k) => VALID_QUESTION_IDS.has(k)).length;
      const answerTexts = POLL_QUESTIONS.map((q) => {
        const choice = s.answers[q.id];
        if (choice === 'A') return q.optionA;
        if (choice === 'B') return q.optionB;
        return '';
      });

      return [
        s.name,
        s.status,
        `${answeredCount}/10`,
        s.joinedAt,
        s.completedAt ?? '',
        ...answerTexts,
      ]
        .map(escapeCsv)
        .join(',');
    });

    return `\uFEFF${[headers.map(escapeCsv).join(','), ...rows].join('\r\n')}`;
  }

  public async startNewSession(label?: string): Promise<SessionPublicInfo> {
    const previous = this.db.activeSession;
    this.db.archivedSessions.unshift(previous);
    if (this.db.archivedSessions.length > 20) {
      this.db.archivedSessions = this.db.archivedSessions.slice(0, 20);
    }
    this.db.activeSession = createFreshSession(label);
    await this.persist();
    return this.getActiveSessionPublic();
  }

  public async resetCurrentSession(): Promise<SessionPublicInfo> {
    this.db.activeSession.students = [];
    this.db.activeSession.createdAt = new Date().toISOString();
    await this.persist();
    return this.getActiveSessionPublic();
  }
}

export const vibeStore = new VibeCheckStore();
