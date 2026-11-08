// Compiler-backed, deliberately bounded CFG facts. No authorization policy lives here.
#include <algorithm>
#include <deque>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/AST/Attr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/ParentMapContext.h"
#include "clang/Analysis/CFG.h"
#include "clang/Basic/DiagnosticOptions.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/TargetInfo.h"
#include "clang/Basic/Version.h"
#include "clang/Frontend/ASTUnit.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Index/USRGeneration.h"
#include "clang/Lex/Lexer.h"
#include "clang/Lex/MacroArgs.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Serialization/ASTReader.h"
#include "clang/Serialization/ModuleFile.h"
#include "clang/Serialization/ModuleManager.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SHA256.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/VirtualFileSystem.h"

using namespace clang;
namespace J = llvm::json;

namespace {
constexpr size_t MaxFunctions = 4096;
constexpr size_t MaxEmissionFunctions = 16384;
constexpr size_t MaxBlocks = 4096;
constexpr size_t MaxSites = 100000;
constexpr size_t MaxGuards = 128;
constexpr size_t MaxSyscallSlots = 2048;

std::string usr(const Decl *D) {
  llvm::SmallString<128> S;
  if (index::generateUSRForDecl(D, S)) return "";
  return std::string(S);
}

std::string pathName(llvm::StringRef Name, const SourceManager &SM) {
  llvm::SmallString<256> Path(Name);
  SM.getFileManager().makeAbsolutePath(Path);
  llvm::sys::path::remove_dots(Path, true);
  return std::string(Path);
}

J::Object point(SourceLocation L, const SourceManager &SM, bool Spelling = false) {
  L = Spelling ? SM.getSpellingLoc(L) : SM.getExpansionLoc(L);
  if (L.isInvalid() || !L.isFileID()) return {};
  return J::Object{{"path", pathName(SM.getFilename(L), SM)}, {"line", SM.getSpellingLineNumber(L)},
          {"column", SM.getSpellingColumnNumber(L)}, {"offset", SM.getFileOffset(L)}};
}

J::Object span(SourceRange R, const ASTContext &C) {
  auto &SM = C.getSourceManager();
  SourceLocation E = Lexer::getLocForEndOfToken(SM.getExpansionLoc(R.getEnd()), 0, SM, C.getLangOpts());
  const bool Macro = R.getBegin().isMacroID() || R.getEnd().isMacroID();
  J::Object Out{{"start", point(R.getBegin(), SM)}, {"end", point(E, SM)}, {"macro", Macro}};
  if (Macro) {
    SourceLocation SpellingEnd = Lexer::getLocForEndOfToken(SM.getSpellingLoc(R.getEnd()), 0, SM, C.getLangOpts());
    Out["spelling_start"] = point(R.getBegin(), SM, true);
    Out["spelling_end"] = point(SpellingEnd, SM, true);
  }
  // File locations have identical expansion/spelling points. Their optional
  // duplicate coordinates otherwise dominate large-TU wire responses.
  return Out;
}

std::string exprText(const Expr *E, const ASTContext &C) {
  std::string S; llvm::raw_string_ostream O(S);
  E->printPretty(O, nullptr, C.getPrintingPolicy());
  return S;
}

J::Array arguments(const CallExpr *Call, const ASTContext &C) {
  J::Array A;
  for (const Expr *E : Call->arguments()) {
    J::Value Number(nullptr);
    Expr::EvalResult Result;
    if (E->EvaluateAsInt(Result, C) && Result.Val.getInt().getSignificantBits() < 64)
      Number = Result.Val.getInt().getSExtValue();
    J::Value Parameter(nullptr);
    if (auto *R = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts()))
      if (auto *P = dyn_cast<ParmVarDecl>(R->getDecl()))
        if (E->getType().getCanonicalType().getUnqualifiedType() ==
            P->getType().getCanonicalType().getUnqualifiedType()) Parameter = P->getFunctionScopeIndex();
    J::Value Declaration(nullptr);
    const Expr *Reference = E->IgnoreParenImpCasts();
    if (const auto *Address = dyn_cast<UnaryOperator>(Reference))
      if (Address->getOpcode() == UO_AddrOf) Reference = Address->getSubExpr()->IgnoreParenImpCasts();
    if (const auto *R = dyn_cast<DeclRefExpr>(Reference)) {
      auto Identity = usr(R->getDecl()->getCanonicalDecl());
      if (!Identity.empty()) Declaration = std::move(Identity);
    }
    A.push_back(J::Object{{"expression", exprText(E, C)}, {"integer", std::move(Number)},
                         {"parameter", std::move(Parameter)}, {"declaration_usr", std::move(Declaration)}});
  }
  return A;
}

const VarDecl *variable(const Expr *E) {
  if (auto *R = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) return dyn_cast<VarDecl>(R->getDecl());
  return nullptr;
}

const CallExpr *directValue(const Expr *E) {
  if (!E) return nullptr;
  E = E->IgnoreParenImpCasts();
  if (auto *C = dyn_cast<CallExpr>(E)) return C->getDirectCallee() ? C : nullptr;
  return nullptr;
}

using Facts = std::map<const VarDecl *, const CallExpr *>;

const CallExpr *sameTypeValue(const VarDecl *V, const Expr *E) {
  if (!V->hasLocalStorage() || V->getType().isVolatileQualified()) return nullptr;
  const auto *Call = directValue(E);
  if (!Call || V->getType().getCanonicalType().getUnqualifiedType() !=
                   Call->getType().getCanonicalType().getUnqualifiedType()) return nullptr;
  return Call;
}

class EscapeVisitor : public RecursiveASTVisitor<EscapeVisitor> {
public:
  std::set<const VarDecl *> escaped;
  std::map<const Stmt *, std::string> writes;
  std::set<unsigned> modifiedParameters;
  bool cleanup = false;
  bool memoryWrite = false;
  bool unmodeledWrite = false;
  bool staticStorage = false;
  bool VisitVarDecl(VarDecl *V) {
    cleanup |= V->hasAttr<CleanupAttr>();
    staticStorage |= V->hasGlobalStorage();
    if (V->hasInit() && V->hasAttr<AsmLabelAttr>()) {
      // A register binding can initialize hardware state without an explicit
      // assignment CFG node. Do not classify it as an ordinary local scalar.
      memoryWrite = true;
      unmodeledWrite = true;
    }
    return true;
  }
  void written(const Expr *E, const Stmt *Site, llvm::StringRef Kind) {
    const auto *V = variable(E);
    // Only assignments to an ordinary automatic scalar have a local effect.
    // Member, pointer, array, global and volatile writes need a memory/subject
    // model before they can preserve the captured credential context.
    if (!V || !V->hasLocalStorage() || !V->getType()->isScalarType() ||
        V->getType().isVolatileQualified() || V->hasAttr<AsmLabelAttr>()) {
      memoryWrite = true;
      writes.emplace(Site, Kind.str());
    }
  }
  void modified(const Expr *E) {
    if (auto *P = dyn_cast_or_null<ParmVarDecl>(variable(E))) modifiedParameters.insert(P->getFunctionScopeIndex());
  }
  bool VisitBinaryOperator(BinaryOperator *B) {
    if (B->isAssignmentOp()) { modified(B->getLHS()); written(B->getLHS(), B, "assignment"); }
    return true;
  }
  bool VisitUnaryOperator(UnaryOperator *U) {
    if (U->getOpcode() == UO_AddrOf)
      if (const auto *V = variable(U->getSubExpr())) escaped.insert(V);
    if (U->getOpcode() == UO_AddrOf || U->isIncrementDecrementOp()) modified(U->getSubExpr());
    if (U->isIncrementDecrementOp()) written(U->getSubExpr(), U, "increment");
    return true;
  }
  bool VisitAtomicExpr(AtomicExpr *A) {
    // Several atomic forms write through an output argument as well as their
    // primary pointer. Until those effects are modeled, retain every form.
    memoryWrite = true;
    writes.emplace(A, "atomic");
    return true;
  }
  bool VisitVAArgExpr(VAArgExpr *) {
    // Reading an argument advances va_list storage, which may be nonlocal.
    // Clang may expose only an enclosing cast as a CFG site; retain until the
    // implicit writes and their exact evaluation points are modeled.
    memoryWrite = true;
    unmodeledWrite = true;
    return true;
  }
};

void transfer(const Stmt *S, Facts &F, const std::set<const VarDecl *> &Escaped) {
  if (auto *D = dyn_cast<DeclStmt>(S)) {
    for (auto *Decl : D->decls()) if (auto *V = dyn_cast<VarDecl>(Decl))
      F[V] = Escaped.count(V) ? nullptr : sameTypeValue(V, V->getInit());
  } else if (auto *B = dyn_cast<BinaryOperator>(S)) {
    if (B->isAssignmentOp()) if (auto *V = variable(B->getLHS()))
      F[V] = B->getOpcode() == BO_Assign && !Escaped.count(V) ? sameTypeValue(V, B->getRHS()) : nullptr;
  } else if (auto *U = dyn_cast<UnaryOperator>(S)) {
    if (U->isIncrementDecrementOp()) if (auto *V = variable(U->getSubExpr())) F[V] = nullptr;
  }
}

std::vector<Facts> reaching(const CFG &Graph, const std::set<const VarDecl *> &Escaped) {
  std::vector<Facts> In(Graph.getNumBlockIDs());
  std::vector<bool> Seen(Graph.getNumBlockIDs(), false);
  std::deque<const CFGBlock *> Work;
  const auto *Entry = &Graph.getEntry(); Seen[Entry->getBlockID()] = true; Work.push_back(Entry);
  while (!Work.empty()) {
    const auto *B = Work.front(); Work.pop_front(); Facts Out = In[B->getBlockID()];
    for (const auto &E : *B) if (auto S = E.getAs<CFGStmt>()) transfer(S->getStmt(), Out, Escaped);
    for (auto I = B->succ_begin(); I != B->succ_end(); ++I) if (const auto *To = I->getReachableBlock()) {
      auto Id = To->getBlockID(); Facts Next;
      if (!Seen[Id]) Next = Out;
      else {
        Next = In[Id];
        for (auto &[V, Value] : Next) {
          auto Found = Out.find(V);
          if (Found == Out.end() || Found->second != Value) Value = nullptr;
        }
        for (auto &[V, Value] : Out) if (!Next.count(V)) Next[V] = nullptr;
      }
      if (!Seen[Id] || Next != In[Id]) { Seen[Id] = true; In[Id] = std::move(Next); Work.push_back(To); }
    }
  }
  return In;
}

struct Condition {
  const CallExpr *call = nullptr;
  std::string yes, no;
};

const CallExpr *rawConditionValue(const Expr *E, const Facts &F) {
  E = E->IgnoreParenImpCasts();
  if (const auto *Call = dyn_cast<CallExpr>(E)) return Call->getDirectCallee() ? Call : nullptr;
  if (const auto *V = variable(E)) {
    auto I = F.find(V); if (I != F.end()) return I->second;
  }
  return nullptr;
}

Condition condition(const Expr *E, const Facts &F) {
  E = E->IgnoreParenImpCasts();
  if (const auto *U = dyn_cast<UnaryOperator>(E)) if (U->getOpcode() == UO_LNot) {
    auto C = condition(U->getSubExpr(), F); std::swap(C.yes, C.no); return C;
  }
  if (const auto *B = dyn_cast<BinaryOperator>(E)) {
    // In the final CFG block of a short-circuit if, previous operands have
    // already selected this path. The rightmost operand controls its edges;
    // edge dominance below still excludes paths that short-circuit around it.
    if (B->getOpcode() == BO_LAnd || B->getOpcode() == BO_LOr) return condition(B->getRHS(), F);
    const Expr *Operand = B->getLHS(); auto Op = B->getOpcode();
    auto *Zero = dyn_cast<IntegerLiteral>(B->getRHS()->IgnoreParenImpCasts());
    if (!Zero || Zero->getValue() != 0) return {};
    auto C = condition(Operand, F); if (!C.call) return {};
    switch (Op) {
    case BO_EQ: std::swap(C.yes, C.no); return C;
    case BO_NE: return C;
    case BO_LT:
      if (!rawConditionValue(Operand, F) || !Operand->getType()->isSignedIntegerType()) return {};
      C.yes = "negative"; C.no = "nonnegative"; return C;
    case BO_GE:
      if (!rawConditionValue(Operand, F) || !Operand->getType()->isSignedIntegerType()) return {};
      C.yes = "nonnegative"; C.no = "negative"; return C;
    default: return {};
    }
  }
  if (const auto *Call = directValue(E)) return {Call, "nonzero", "zero"};
  if (const auto *V = variable(E)) {
    auto I = F.find(V); if (I != F.end() && I->second) return {I->second, "nonzero", "zero"};
  }
  return {};
}

struct Guard {
  unsigned branch, successor;
  const CallExpr *call;
  std::string outcome;
};

using SitePosition = std::pair<unsigned, unsigned>;
using SitePositions = std::map<const Stmt *, std::vector<SitePosition>>;

struct Constraint {
  unsigned branch, successor, parameter;
  int64_t integer;
};

std::set<unsigned> reachable(const CFG &Graph, unsigned SkipBranch, unsigned SkipSuccessor) {
  std::set<unsigned> Seen; std::deque<const CFGBlock *> Work{&Graph.getEntry()};
  while (!Work.empty()) {
    const auto *B = Work.front(); Work.pop_front();
    if (!Seen.insert(B->getBlockID()).second) continue;
    unsigned Position = 0;
    for (auto I = B->succ_begin(); I != B->succ_end(); ++I, ++Position) {
      if (B->getBlockID() == SkipBranch && Position == SkipSuccessor) continue;
      if (const auto *To = I->getReachableBlock()) Work.push_back(To);
    }
  }
  return Seen;
}

J::Object guardJson(const Guard &G, const ASTContext &C, const SitePositions &Positions) {
  const auto *F = G.call->getDirectCallee();
  J::Value Block(nullptr), Order(nullptr);
  auto Found = Positions.find(G.call);
  if (Found != Positions.end() && Found->second.size() == 1) {
    Block = Found->second.front().first;
    Order = Found->second.front().second;
  }
  return J::Object{{"callee", F->getNameAsString()}, {"callee_usr", usr(F)},
          {"arguments", arguments(G.call, C)}, {"outcome", G.outcome},
          {"span", span(G.call->getSourceRange(), C)},
          {"call_block", std::move(Block)}, {"call_order", std::move(Order)}};
}

J::Array obligations(unsigned Block, const std::vector<Guard> &Guards,
                     const std::vector<std::set<unsigned>> &Bypass, const ASTContext &C,
                     const SitePositions &Positions) {
  J::Array A;
  for (size_t I = 0; I < Guards.size(); ++I)
    if (!Bypass[I].count(Block)) A.push_back(guardJson(Guards[I], C, Positions));
  return A;
}

J::Array constraints(unsigned Block, const std::vector<Constraint> &Constraints,
                     const std::vector<std::set<unsigned>> &Bypass) {
  J::Array A;
  for (size_t I = 0; I < Constraints.size(); ++I) if (!Bypass[I].count(Block))
    A.push_back(J::Object{{"parameter", Constraints[I].parameter},
                         {"integer", Constraints[I].integer}, {"relation", "eq"}});
  return A;
}

bool cIdentifier(llvm::StringRef S) {
  return !S.empty() && (llvm::isAlpha(S.front()) || S.front() == '_') &&
    std::all_of(S.begin(), S.end(), [](char Ch) { return llvm::isAlnum(Ch) || Ch == '_'; });
}

std::string compact(llvm::StringRef S) {
  std::string Out;
  for (char Ch : S) if (!llvm::isSpace(Ch)) Out += Ch;
  return Out;
}

bool asmStrings(llvm::StringRef S, bool Terminated = false) {
  llvm::StringRef Last;
  unsigned Count = 0;
  for (S = S.trim(); !S.empty(); S = S.trim()) {
    if (S.front() != '"') return false;
    size_t End = 1;
    for (; End < S.size() && S[End] != '"'; ++End) {
      char Ch = S[End];
      if (Ch < 32 || Ch > 126) return false;
      if (Ch == '\\') {
        if (++End >= S.size() || (S[End] != '\\' && S[End] != '"' && (S[End] < '0' || S[End] > '7'))) return false;
      }
    }
    if (End >= S.size()) return false;
    Last = S.take_front(End + 1); S = S.drop_front(End + 1); ++Count;
  }
  return Terminated ? Count >= 2 && Last == R"("\0")" : Count == 1;
}

bool trustedAsmMacro(FileScopeAsmDecl *D, llvm::StringRef Name, llvm::StringRef Header, const ASTContext &C) {
  auto &SM = C.getSourceManager(); auto L = D->getBeginLoc();
  while (L.isMacroID()) {
    if (Lexer::getImmediateMacroName(L, SM, C.getLangOpts()) == Name &&
        SM.getFilename(SM.getSpellingLoc(L)).ends_with(Header)) return true;
    L = SM.getImmediateMacroCallerLoc(L);
  }
  return false;
}

std::vector<llvm::StringRef> asmParts(llvm::StringRef Text) {
  if (Text.size() > 16384) return {};
  std::vector<llvm::StringRef> Parts;
  bool Quoted = false, Escaped = false;
  size_t Start = 0;
  for (size_t I = 0; I < Text.size(); ++I) {
    char Ch = Text[I];
    if (Escaped) { Escaped = false; continue; }
    if (Quoted && Ch == '\\') { Escaped = true; continue; }
    if (Ch == '"') { Quoted = !Quoted; continue; }
    if (!Quoted && (Ch == ';' || Ch == '\n')) {
      auto Part = Text.slice(Start, I).trim(); if (!Part.empty()) Parts.push_back(Part); Start = I + 1;
    }
  }
  auto Last = Text.drop_front(Start).trim(); if (!Last.empty()) Parts.push_back(Last);
  return Quoted || Escaped ? std::vector<llvm::StringRef>{} : Parts;
}

std::string readonlyExport(FileScopeAsmDecl *D, llvm::StringRef Text, const ASTContext &C) {
  if (!trustedAsmMacro(D, "__EXPORT_SYMBOL", "/include/linux/export.h", C)) return "";
  // No executable flags/instructions, aliases, arithmetic relocations, extra
  // sections, or arbitrary assembler directives are accepted by these models.
  auto Parts = asmParts(Text);
  if (Parts.size() != 7 || compact(Parts[0]) != ".section\".export_symbol\",\"a\"" ||
      Parts[6] != ".previous") return "";
  auto Label = Parts[1];
  if (!Label.consume_front("__export_symbol_") || !Label.consume_back(":") || !cIdentifier(Label)) return "";
  auto License = Parts[2], Namespace = Parts[3];
  if (!License.consume_front(".asciz") || !asmStrings(License) ||
      !Namespace.consume_front(".ascii") || !asmStrings(Namespace, true)) return "";
  auto Alignment = compact(Parts[4]), Reference = compact(Parts[5]);
  if (!((Alignment == ".balign8" && Reference == ".quad" + Label.str()) ||
        (Alignment == ".balign4" && Reference == ".long" + Label.str()))) return "";
  return Label.str();
}

struct ReadonlyAssembly {
  enum TargetKind { AnyValue, Function, Object } targetKind = AnyValue;
  std::string kind = "unknown", symbol;
};

ReadonlyAssembly readonlyInitcall(FileScopeAsmDecl *D, llvm::StringRef Text, const ASTContext &C) {
  if (!trustedAsmMacro(D, "____define_initcall", "/include/linux/init.h", C)) return {};
  auto Parts = asmParts(Text);
  if (Parts.size() != 4 || Parts[3] != ".previous") return {};
  auto Section = compact(Parts[0]);
  const std::set<std::string> Levels{"early", "0", "1", "1s", "2", "2s", "3", "3s", "4", "4s",
                                     "5", "5s", "rootfs", "6", "6s", "7", "7s"};
  bool ValidSection = Section == ".section\".con_initcall.init\",\"a\"";
  for (const auto &Level : Levels) ValidSection |= Section == ".section\".initcall" + Level + ".init\",\"a\"";
  auto Label = Parts[1];
  auto Reference = compact(Parts[2]);
  llvm::StringRef Name(Reference);
  if (!ValidSection || !Label.consume_front("__initcall__") || !Label.consume_back(":") || !cIdentifier(Label) ||
      !Name.consume_front(".long") || !Name.consume_back("-.") || !cIdentifier(Name)) return {};
  return {ReadonlyAssembly::Function, "readonly_initcall", Name.str()};
}

ReadonlyAssembly readonlyBtf(FileScopeAsmDecl *D, llvm::StringRef Text, const ASTContext &C) {
  auto Parts = asmParts(Text);
  if (Parts.size() < 4 || compact(Parts.front()) != ".pushsection.BTF_ids,\"a\"" || Parts.back() != ".popsection") return {};
  auto Label = Parts[2];
  // SourceManager can collapse the first token's nested macro expansions to
  // the public wrapper. Each accepted carrier is defined in the pinned header;
  // the assembler grammar and resolved object identity are still mandatory.
  bool TrustedList = false;
  for (auto Name : {"__BTF_ID_LIST", "BTF_ID_LIST", "BTF_ID_LIST_GLOBAL", "BTF_ID_LIST_SINGLE", "BTF_ID_LIST_GLOBAL_SINGLE"})
    TrustedList |= trustedAsmMacro(D, Name, "/include/linux/btf_ids.h", C);
  if (Parts.size() == 4 && TrustedList) {
    if (!Label.consume_back(":") || !cIdentifier(Label)) return {};
    auto Binding = compact(Parts[1]);
    if (Binding != ".local" + Label.str() && Binding != ".globl" + Label.str()) return {};
    return {ReadonlyAssembly::Object, "readonly_btf", Label.str()};
  }
  if (Parts.size() != 7 || !trustedAsmMacro(D, "____BTF_ID", "/include/linux/btf_ids.h", C)) return {};
  Label = Parts[4];
  if (!Label.consume_back(":") || !cIdentifier(Label) || compact(Parts[1]) != ".local" + Label.str() ||
      compact(Parts[2]) != ".type" + Label.str() + ",STT_OBJECT" ||
      compact(Parts[3]) != ".size" + Label.str() + ",4" || compact(Parts[5]) != ".zero4") return {};
  // Only function IDs have a modeled execution reference. Type/set/flags
  // records and unresolved cross-TU symbols stay unknown in this first model.
  if (!Label.consume_front("__BTF_ID__func__")) return {};
  auto Separator = Label.rfind("__");
  if (Separator == llvm::StringRef::npos) return {};
  auto Name = Label.take_front(Separator), Counter = Label.drop_front(Separator + 2);
  if (!cIdentifier(Name) || Counter.empty() || !std::all_of(Counter.begin(), Counter.end(), llvm::isDigit)) return {};
  return {ReadonlyAssembly::Function, "readonly_btf", Name.str()};
}

SourceRange tracepointMacroOrigin(SourceLocation L, const ASTContext &C) {
  auto &SM = C.getSourceManager();
  while (L.isMacroID()) {
    // Pair the name and spelling location at this expansion level; a flattened
    // inner token must not lend trust to an unrelated outer macro name.
    auto Spelling = SM.getImmediateSpellingLoc(L);
    if (Lexer::getImmediateMacroName(L, SM, C.getLangOpts()) == "__TRACEPOINT_ENTRY" &&
        Spelling.isFileID() && SM.getFilename(Spelling).ends_with("/include/linux/tracepoint.h"))
      return SM.getImmediateExpansionRange(L).getAsRange();
    L = SM.getImmediateMacroCallerLoc(L);
  }
  return {};
}

llvm::StringRef asmOperand(llvm::StringRef Part, llvm::StringRef Directive) {
  if (!Part.consume_front(Directive) || Part.empty() || !llvm::isSpace(Part.front())) return {};
  return Part.trim();
}

ReadonlyAssembly readonlyTracepoint(FileScopeAsmDecl *D, llvm::StringRef Text, const ASTContext &C) {
  const auto BeginOrigin = tracepointMacroOrigin(D->getBeginLoc(), C);
  const auto EndOrigin = tracepointMacroOrigin(D->getEndLoc(), C);
  if (BeginOrigin.isInvalid() || BeginOrigin != EndOrigin) return {};
  auto Parts = asmParts(Text);
  if (Parts.size() != 4 || Parts[3] != ".previous" || asmOperand(Parts[1], ".balign") != "4") return {};
  auto Section = asmOperand(Parts[0], ".section");
  if (!Section.consume_front("\"__tracepoints_ptrs\"")) return {};
  Section = Section.trim();
  if (!Section.consume_front(",") || Section.trim() != "\"a\"") return {};
  auto Reference = asmOperand(Parts[2], ".long");
  size_t End = 0;
  while (End < Reference.size() && (llvm::isAlnum(Reference[End]) || Reference[End] == '_')) ++End;
  const auto Symbol = Reference.take_front(End);
  auto Name = Symbol;
  Reference = Reference.drop_front(End).trim();
  if (Symbol.size() > 256 || !Name.consume_front("__tracepoint_") || !cIdentifier(Name) ||
      !Reference.consume_front("-") || Reference.trim() != ".") return {};
  return {ReadonlyAssembly::Object, "readonly_tracepoint", Symbol.str()};
}

class EntryClosureVisitor : public RecursiveASTVisitor<EntryClosureVisitor> {
  ASTContext &C;
  const std::set<std::string> &Paths, &Names;
  std::vector<const FunctionDecl *> Targets;
  std::vector<QualType> IndirectTypes;
  size_t Nodes = 0, TextBytes = 0;
  bool room() {
    if (inlineAssembly.size() + indirectCalls.size() >= 4096) { complete = false; return false; }
    return true;
  }
  bool sourceRange(SourceRange R) {
    auto &SM = C.getSourceManager();
    const auto Begin = SM.getExpansionLoc(R.getBegin()), End = SM.getExpansionLoc(R.getEnd());
    if (Begin.isInvalid() || End.isInvalid() || !Begin.isFileID() || !End.isFileID()) {
      complete = false; return false;
    }
    return true;
  }
public:
  EntryClosureVisitor(ASTContext &C, const std::set<std::string> &P, const std::set<std::string> &N)
    : C(C), Paths(P), Names(N) {
    if (C.getLangOpts().CPlusPlus || C.getLangOpts().ObjC || C.getLangOpts().OpenCL) complete = false;
  }
  bool complete = true;
  bool targetCoverageComplete = true;
  J::Array inlineAssembly, indirectCalls;
  bool VisitFunctionDecl(FunctionDecl *F) {
    if (!F->doesThisDeclarationHaveABody() || F->isImplicit()) return true;
    const auto &SM = C.getSourceManager();
    const auto L = SM.getExpansionLoc(F->getBeginLoc());
    if (!Paths.count(pathName(SM.getFilename(L), SM)) || (!Names.empty() && !Names.count(F->getNameAsString()))) return true;
    if (Targets.size() >= MaxFunctions) { complete = false; return false; }
    Targets.push_back(F);
    return true;
  }
  J::Array indirectTargets() {
    std::set<std::string> Matches;
    size_t Comparisons = 0;
    for (const auto *F : Targets) for (const auto &Type : IndirectTypes) {
      if (++Comparisons > MaxSites) { targetCoverageComplete = false; return {}; }
      // These are possible targets under ordinary, type-compatible C calls.
      // An old-style/unresolved call type cannot rule out any tracked target.
      if (Type.isNull() || Type->isFunctionNoProtoType() || C.typesAreCompatible(Type, F->getType())) {
        Matches.insert(usr(F)); break;
      }
    }
    J::Array Result;
    for (const auto &Name : Matches) Result.push_back(Name);
    return Result;
  }
  bool VisitStmt(Stmt *S) {
    if (++Nodes > 1000000) { complete = false; return false; }
    if (isa<CapturedStmt, BlockExpr, IndirectGotoStmt>(S)) complete = false;
    const auto *Assembly = dyn_cast<AsmStmt>(S);
    if (!Assembly) return true;
    if (!room() || !sourceRange(S->getSourceRange())) return false;
    std::string Text;
    bool EmptyBarrier = false;
    if (const auto *GCC = dyn_cast<GCCAsmStmt>(Assembly)) {
      Text = GCC->getAsmString();
      EmptyBarrier = Text.empty() && !GCC->getNumOutputs() && !GCC->getNumInputs() && !GCC->getNumLabels();
      for (unsigned I = 0; I < GCC->getNumClobbers(); ++I)
        EmptyBarrier &= GCC->getClobber(I) == "memory";
    } else if (const auto *MS = dyn_cast<MSAsmStmt>(Assembly)) {
      Text = MS->getAsmString().str(); complete = false;
    }
    else complete = false;
    TextBytes += Text.size();
    if (Text.size() > 16384 || TextBytes > 1024 * 1024) { complete = false; return false; }
    inlineAssembly.push_back(J::Object{{"span", span(S->getSourceRange(), C)}, {"text", Text},
      {"kind", EmptyBarrier ? "empty_barrier" : "opaque"}});
    return true;
  }
  bool VisitCallExpr(CallExpr *Call) {
    if (Call->getDirectCallee()) return true;
    if (!room() || !sourceRange(Call->getSourceRange())) return false;
    indirectCalls.push_back(span(Call->getSourceRange(), C));
    const auto Type = Call->getCallee()->getType();
    IndirectTypes.push_back(Type->isPointerType() ? Type->getPointeeType() : QualType());
    return true;
  }
};

class BodyTranslationVisitor : public RecursiveASTVisitor<BodyTranslationVisitor> {
  struct MetadataSite { SourceLocation begin, end; };
  const ASTContext &C;
  const FunctionDecl *Root;
  size_t Nodes = 0;
  std::vector<MetadataSite> MetadataSites;
  std::set<std::pair<unsigned, unsigned>> MetadataSeen;
  void metadata(SourceRange R) {
    auto &SM = C.getSourceManager();
    const auto Begin = SM.getExpansionLoc(R.getBegin());
    const auto End = Lexer::getLocForEndOfToken(SM.getExpansionLoc(R.getEnd()), 0, SM, C.getLangOpts());
    const auto BodyBegin = SM.getExpansionLoc(Root->getBody()->getBeginLoc());
    const auto BodyEnd = SM.getExpansionLoc(Root->getBody()->getEndLoc());
    if (Begin.isInvalid() || End.isInvalid() || !Begin.isFileID() || !End.isFileID() ||
        SM.getFileID(Begin) != SM.getFileID(End) || SM.getFileID(Begin) != SM.getFileID(BodyBegin) ||
        SM.getFileID(Begin) != SM.getFileID(BodyEnd) || SM.getFileOffset(End) <= SM.getFileOffset(Begin)) {
      metadataComplete = false; return;
    }
    const auto Key = std::make_pair(Begin.getRawEncoding(), End.getRawEncoding());
    if (MetadataSeen.count(Key)) return;
    if (MetadataSites.size() >= 4096) { metadataComplete = false; return; }
    MetadataSeen.insert(Key);
    MetadataSites.push_back({Begin, End});
  }
public:
  BodyTranslationVisitor(const FunctionDecl *F, const ASTContext &C) : C(C), Root(F) {}
  bool complete = true;
  bool metadataComplete = true;
  std::set<std::string> effects;
  J::Array metadataSpans() const {
    auto &SM = C.getSourceManager();
    auto Sites = MetadataSites;
    std::sort(Sites.begin(), Sites.end(), [&](const auto &A, const auto &B) {
      if (SM.getFileOffset(A.begin) != SM.getFileOffset(B.begin))
        return SM.getFileOffset(A.begin) < SM.getFileOffset(B.begin);
      return SM.getFileOffset(A.end) > SM.getFileOffset(B.end);
    });
    std::vector<MetadataSite> Normalized;
    for (const auto &Site : Sites) {
      if (!Normalized.empty() && SM.getFileOffset(Site.begin) <= SM.getFileOffset(Normalized.back().end)) {
        if (SM.getFileOffset(Site.end) > SM.getFileOffset(Normalized.back().end)) Normalized.back().end = Site.end;
      } else Normalized.push_back(Site);
    }
    J::Array Result;
    for (const auto &Site : Normalized)
      Result.push_back(J::Object{{"path", pathName(SM.getFilename(Site.begin), SM)},
        {"start", SM.getFileOffset(Site.begin)}, {"end", SM.getFileOffset(Site.end)}});
    return Result;
  }
  bool VisitTypeLoc(TypeLoc T) {
    if (++Nodes > MaxSites) { complete = metadataComplete = false; effects.insert("declaration_inventory_budget"); return false; }
    metadata(T.getSourceRange());
    // Tags introduced in sizeof, casts, compound literals, _Generic, or
    // typeof are not DeclStmt children. Do not follow referenced global types.
    const auto *Tag = T.getType()->getAsTagDecl();
    if (!Tag) return true;
    for (const auto *Context = Tag->getLexicalDeclContext(); Context; Context = Context->getParent())
      if (Context == Root) { effects.insert("body_tag_declaration"); break; }
    return true;
  }
  bool VisitStmt(Stmt *S) {
    if (++Nodes > MaxSites) { complete = metadataComplete = false; effects.insert("declaration_inventory_budget"); return false; }
    if (const auto *Label = dyn_cast<LabelStmt>(S)) metadata(SourceRange(Label->getIdentLoc()));
    else if (isa<DeclStmt, DeclRefExpr, MemberExpr, PredefinedExpr, GotoStmt, AddrLabelExpr>(S))
      metadata(S->getSourceRange());
    if (isa<AsmStmt>(S)) effects.insert("body_assembly");
    if (isa<CapturedStmt, BlockExpr>(S)) { complete = metadataComplete = false; effects.insert("captured_statement_not_modeled"); }
    return true;
  }
  bool VisitDecl(Decl *D) {
    if (++Nodes > MaxSites) { complete = metadataComplete = false; effects.insert("declaration_inventory_budget"); return false; }
    for (const auto *A : D->attrs())
      if (!isa<CleanupAttr, UnusedAttr>(A)) effects.insert("body_declaration_attribute");
    if (const auto *V = dyn_cast<VarDecl>(D)) {
      if (!V->hasLocalStorage() || V->getTLSKind() != VarDecl::TLS_None)
        effects.insert("nonautomatic_body_variable");
    } else if (isa<FunctionDecl>(D)) effects.insert("block_function_declaration");
    else if (isa<TypedefNameDecl>(D)) effects.insert("body_typedef");
    else if (isa<TagDecl>(D)) effects.insert("body_tag_declaration");
    else if (!isa<FieldDecl, EnumConstantDecl, LabelDecl, IndirectFieldDecl, EmptyDecl>(D)) {
      complete = metadataComplete = false; effects.insert("body_declaration_not_modeled");
    }
    return true;
  }
};

struct EmissionNode {
  const FunctionDecl *function;
  std::string identity;
  std::set<std::string> callees, effects;
  std::vector<QualType> indirect;
  std::vector<std::string> assembly;
};

class EmissionBodyVisitor : public RecursiveASTVisitor<EmissionBodyVisitor> {
  EmissionNode &Node;
  size_t &Sites;
public:
  EmissionBodyVisitor(EmissionNode &N, size_t &S) : Node(N), Sites(S) {}
  bool VisitStmt(Stmt *S) {
    if (++Sites > 1000000) return false;
    if (const auto *Assembly = dyn_cast<GCCAsmStmt>(S)) Node.assembly.push_back(Assembly->getAsmString());
    else if (isa<AsmStmt>(S)) Node.effects.insert("unmodeled_assembly");
    if (isa<CapturedStmt, BlockExpr>(S)) Node.effects.insert("captured_codegen");
    return true;
  }
  bool VisitCallExpr(CallExpr *Call) {
    if (const auto *Target = Call->getDirectCallee()) Node.callees.insert(usr(Target));
    else {
      const auto Type = Call->getCallee()->getType();
      Node.indirect.push_back(Type->isPointerType() ? Type->getPointeeType() : QualType());
    }
    return true;
  }
  bool VisitVarDecl(VarDecl *V) {
    if (V->hasLocalStorage()) return true;
    if (const auto *Section = V->getAttr<SectionAttr>())
      Node.effects.insert("sectioned_storage:" + Section->getName().str());
    if (V->hasAttr<AsmLabelAttr>() || V->hasAttr<AliasAttr>() || V->hasAttr<IFuncAttr>())
      Node.effects.insert("assembler_named_storage");
    return true;
  }
};

class EmissionVisitor : public RecursiveASTVisitor<EmissionVisitor> {
  ASTContext &C;
  size_t Sites = 0;
  std::vector<EmissionNode> Nodes;
public:
  explicit EmissionVisitor(ASTContext &Context) : C(Context) {}
  bool complete = true;
  bool VisitFunctionDecl(FunctionDecl *F) {
    if (!F->doesThisDeclarationHaveABody() || F->isImplicit()) return true;
    if (Nodes.size() >= MaxEmissionFunctions) { complete = false; return false; }
    EmissionNode Node{F, usr(F), {}, {}, {}, {}};
    if (Node.identity.empty()) { complete = false; return false; }
    EmissionBodyVisitor Body(Node, Sites);
    if (!Body.TraverseStmt(F->getBody())) { complete = false; return false; }
    Nodes.push_back(std::move(Node));
    return true;
  }
  J::Array finish(const J::Array &References) {
    std::set<std::string> Escaped;
    for (const auto &Reference : References)
      if (const auto *Object = Reference.getAsObject())
        if (auto Name = Object->getString("usr")) Escaped.insert(Name->str());
    size_t Comparisons = 0, Edges = 0, Text = 0;
    J::Array Result;
    for (auto &Node : Nodes) {
      for (const auto &Type : Node.indirect) for (const auto &Target : Nodes) {
        const auto &Name = Target.identity;
        if (!Escaped.count(Name)) continue;
        if (++Comparisons > 500000) { complete = false; return {}; }
        if (Type.isNull() || Type->isFunctionNoProtoType() || C.typesAreCompatible(Type, Target.function->getType()))
          Node.callees.insert(Name);
      }
      J::Array Calls, Effects, Assembly;
      Edges += Node.callees.size();
      if (Edges > MaxSites) { complete = false; return {}; }
      for (const auto &Name : Node.callees) Calls.push_back(Name);
      for (const auto &Effect : Node.effects) Effects.push_back(Effect);
      for (const auto &Code : Node.assembly) {
        Text += Code.size();
        if (Code.size() > 16384 || Text > 1024 * 1024) { complete = false; return {}; }
        Assembly.push_back(Code);
      }
      Result.push_back(J::Object{{"name", Node.function->getNameAsString()}, {"usr", Node.identity},
        {"callees", std::move(Calls)}, {"effects", std::move(Effects)}, {"assembly", std::move(Assembly)}});
    }
    return Result;
  }
};

class FunctionVisitor : public RecursiveASTVisitor<FunctionVisitor> {
  ASTContext &C;
  const std::set<std::string> &Paths, &Names;
  size_t Sites = 0;
public:
  J::Array functions;
  J::Array addressTaken;
  J::Array fileAssembly;
  std::set<std::string> unknowns;
  FunctionVisitor(ASTContext &C, const std::set<std::string> &P, const std::set<std::string> &N) : C(C), Paths(P), Names(N) {}

  bool VisitFileScopeAsmDecl(FileScopeAsmDecl *D) {
    if (fileAssembly.size() >= 4096) { unknowns.insert("assembly_budget"); return false; }
    auto Text = D->getAsmString();
    ReadonlyAssembly Model;
    if (auto Name = readonlyExport(D, Text, C); !Name.empty()) Model = {ReadonlyAssembly::AnyValue, "readonly_export", Name};
    else if (auto Initcall = readonlyInitcall(D, Text, C); !Initcall.symbol.empty()) Model = std::move(Initcall);
    else if (auto Btf = readonlyBtf(D, Text, C); !Btf.symbol.empty()) Model = std::move(Btf);
    else Model = readonlyTracepoint(D, Text, C);
    const auto &Name = Model.symbol;
    const ValueDecl *Target = nullptr;
    if (!Name.empty()) for (auto *Candidate : C.getTranslationUnitDecl()->lookup(&C.Idents.get(Name))) {
      if (auto *Value = dyn_cast<ValueDecl>(Candidate)) {
        if ((Model.targetKind == ReadonlyAssembly::Function && !isa<FunctionDecl>(Value)) ||
            (Model.targetKind == ReadonlyAssembly::Object && !isa<VarDecl>(Value))) { Target = nullptr; break; }
        if (Value->hasAttr<AsmLabelAttr>() || Value->hasAttr<AliasAttr>() || Value->hasAttr<IFuncAttr>()) { Target = nullptr; break; }
        if (Model.kind == "readonly_tracepoint") {
          const auto *Object = dyn_cast<VarDecl>(Value);
          bool Unmodeled = !Object || !Object->isFileVarDecl() || Object->getTLSKind() != VarDecl::TLS_None;
          if (Object) for (const auto *Declaration : Object->redecls())
            Unmodeled |= Declaration->hasAttr<AsmLabelAttr>() || Declaration->hasAttr<AliasAttr>() ||
                         Declaration->hasAttr<IFuncAttr>() || Declaration->hasAttr<WeakAttr>() || Declaration->hasAttr<WeakRefAttr>();
          if (Unmodeled) { Target = nullptr; break; }
        }
        if (Target && Target->getCanonicalDecl() != Value->getCanonicalDecl()) { Target = nullptr; break; }
        Target = Value;
      }
    }
    J::Array Symbols;
    if (Target && !usr(Target).empty() && addressTaken.size() < MaxSites) {
      Symbols.push_back(Name);
      addressTaken.push_back(J::Object{{"name", Name}, {"usr", usr(Target)}, {"span", span(D->getSourceRange(), C)}});
    } else unknowns.insert("file_scope_assembly");
    fileAssembly.push_back(J::Object{{"span", span(D->getSourceRange(), C)}, {"text", Text.substr(0, 16384)},
      {"kind", Target ? Model.kind : "unknown"}, {"symbols", std::move(Symbols)}});
    return true;
  }

  bool VisitDeclRefExpr(DeclRefExpr *R) {
    auto *F = dyn_cast<FunctionDecl>(R->getDecl());
    if (!F) return true;
    auto &SM = C.getSourceManager();
    const auto *Definition = F->getDefinition();
    // A single compiled .c may include header-defined callers. Their bodies
    // are outside the requested extraction paths, so even a direct call there
    // prevents a complete caller closure for a tracked definition. Expansion
    // locations keep main-file-generated syscall wrappers in the tracked TU.
    bool UntrackedCaller = Definition &&
      Paths.count(pathName(SM.getFilename(SM.getExpansionLoc(Definition->getBeginLoc())), SM)) &&
      !Paths.count(pathName(SM.getFilename(SM.getExpansionLoc(R->getExprLoc())), SM));
    const Stmt *Current = R;
    auto Parents = C.getParents(*Current);
    while (Parents.size() == 1 && Parents[0].get<Expr>()) {
      auto *E = Parents[0].get<Expr>();
      if (const auto *Call = dyn_cast<CallExpr>(E)) {
        if (Call->getCallee()->IgnoreParenImpCasts() == R && !UntrackedCaller) return true;
        break;
      }
      if (!isa<ImplicitCastExpr, ParenExpr>(E)) break;
      Current = E; Parents = C.getParents(*Current);
    }
    if (addressTaken.size() >= MaxSites) { unknowns.insert("reference_budget"); return false; }
    addressTaken.push_back(J::Object{{"name", F->getNameAsString()}, {"usr", usr(F)},
                                    {"span", span(R->getSourceRange(), C)}});
    return true;
  }

  bool VisitVarDecl(VarDecl *V) {
    if (V->hasAttr<AliasAttr>() || V->hasAttr<IFuncAttr>()) unknowns.insert("alias_not_modeled");
    if (const auto *Cleanup = V->getAttr<CleanupAttr>()) {
      const auto *Function = Cleanup->getFunctionDecl();
      if (!Function || usr(Function->getCanonicalDecl()).empty()) unknowns.insert("cleanup_target_not_modeled");
      else {
        if (addressTaken.size() >= MaxSites) { unknowns.insert("reference_budget"); return false; }
        addressTaken.push_back(J::Object{{"name", Function->getNameAsString()},
          {"usr", usr(Function->getCanonicalDecl())}, {"span", span(V->getSourceRange(), C)}});
      }
    }
    if (const auto *Label = V->getAttr<AsmLabelAttr>()) {
      for (auto *D : C.getTranslationUnitDecl()->lookup(&C.Idents.get(Label->getLabel()))) {
        const auto *Target = dyn_cast<FunctionDecl>(D);
        const auto *Definition = Target ? Target->getDefinition() : nullptr;
        auto &SM = C.getSourceManager();
        if (!Definition || !Paths.count(pathName(SM.getFilename(SM.getExpansionLoc(Definition->getBeginLoc())), SM))) continue;
        if (addressTaken.size() >= MaxSites) { unknowns.insert("reference_budget"); return false; }
        addressTaken.push_back(J::Object{{"name", Target->getNameAsString()}, {"usr", usr(Target)},
                                       {"span", span(V->getSourceRange(), C)}});
      }
    }
    return true;
  }

  bool VisitFunctionDecl(FunctionDecl *F) {
    if (F->hasAttr<AliasAttr>() || F->hasAttr<IFuncAttr>()) unknowns.insert("alias_not_modeled");
    if (const auto *Label = F->getAttr<AsmLabelAttr>()) {
      std::set<const FunctionDecl *> Targets{F->getCanonicalDecl()};
      for (auto *D : C.getTranslationUnitDecl()->lookup(&C.Idents.get(Label->getLabel())))
        if (const auto *Target = dyn_cast<FunctionDecl>(D)) Targets.insert(Target->getCanonicalDecl());
      for (const auto *Target : Targets) if (const auto *Definition = Target->getDefinition()) {
        auto &SM = C.getSourceManager();
        if (!Paths.count(pathName(SM.getFilename(SM.getExpansionLoc(Definition->getBeginLoc())), SM))) continue;
        if (addressTaken.size() >= MaxSites) { unknowns.insert("reference_budget"); return false; }
        addressTaken.push_back(J::Object{{"name", Target->getNameAsString()}, {"usr", usr(Target)},
                                       {"span", span(F->getSourceRange(), C)}});
      }
    }
    if (!F->doesThisDeclarationHaveABody() || F->isImplicit()) return true;
    auto &SM = C.getSourceManager(); auto L = SM.getExpansionLoc(F->getBeginLoc());
    std::string Path = pathName(SM.getFilename(L), SM);
    if (!Paths.count(Path) || (!Names.empty() && !Names.count(F->getNameAsString()))) return true;
    if (functions.size() >= MaxFunctions) { unknowns.insert("function_budget"); return false; }
    J::Array Unknown;
    if (F->getBeginLoc().isMacroID() || F->getEndLoc().isMacroID()) Unknown.push_back("macro_function_definition");
    CFG::BuildOptions Options;
    Options.AddInitializers = true;
    auto Graph = CFG::buildCFG(F, F->getBody(), &C, Options);
    if (!Graph || Graph->getNumBlockIDs() > MaxBlocks) { unknowns.insert("cfg_budget_or_failure"); return true; }
    EscapeVisitor Escapes; Escapes.TraverseStmt(F->getBody());
    BodyTranslationVisitor Translation(F, C);
    if (!Translation.TraverseStmt(F->getBody())) Translation.complete = Translation.metadataComplete = false;
    if (C.getLangOpts().CPlusPlus || C.getLangOpts().ObjC || C.getLangOpts().OpenCL)
      Translation.complete = Translation.metadataComplete = false;
    J::Array TranslationEffects;
    for (const auto &Effect : Translation.effects) TranslationEffects.push_back(Effect);
    if (Escapes.cleanup) Unknown.push_back("cleanup_attribute");
    if (Escapes.staticStorage) Unknown.push_back("static_storage_declaration");
    if (F->hasAttr<ConstructorAttr>() || F->hasAttr<DestructorAttr>() ||
        F->hasAttr<AliasAttr>() || F->hasAttr<SectionAttr>() || F->hasAttr<UsedAttr>())
      Unknown.push_back("special_function_attribute");
    auto In = reaching(*Graph, Escapes.escaped);
    const auto Reachable = reachable(*Graph, ~0U, ~0U);
    SitePositions Positions;
    J::Array Blocks;
    std::set<const Stmt *> AccountedWrites;
    for (const auto *B : *Graph) {
      J::Array Successors;
      for (auto I = B->succ_begin(); I != B->succ_end(); ++I)
        if (const auto *To = I->getReachableBlock()) Successors.push_back(To->getBlockID());
      Blocks.push_back(J::Object{{"block", B->getBlockID()}, {"successors", std::move(Successors)}});
      unsigned Order = 0;
      for (const auto &E : *B) {
        if (auto S = E.getAs<CFGStmt>()) {
          const Stmt *Node = S->getStmt();
          Positions[Node].emplace_back(B->getBlockID(), Order);
          const auto Range = Node->getSourceRange();
          const auto Begin = SM.getExpansionLoc(Range.getBegin());
          const auto End = SM.getExpansionLoc(Range.getEnd());
          if (Escapes.writes.count(Node) && Begin.isValid() && End.isValid() &&
              Begin.isFileID() && End.isFileID() && !SM.getFilename(Begin).empty() && !SM.getFilename(End).empty())
            AccountedWrites.insert(Node);
        }
        ++Order;
      }
    }
    const bool WriteCoverageComplete = !Escapes.unmodeledWrite && std::all_of(Escapes.writes.begin(), Escapes.writes.end(),
      [&](const auto &Write) { return AccountedWrites.count(Write.first); });
    // A missing site may hide an evaluated macro/atomic expression. Its absence
    // from CFG effects never establishes that the function preserves subjects.
    if (Escapes.memoryWrite && !WriteCoverageComplete) Unknown.push_back("memory_write");
    std::vector<Guard> Guards;
    std::vector<Constraint> Constraints;
    for (const auto *B : *Graph) {
      if (B->succ_size() != 2 || !Reachable.count(B->getBlockID())) continue;
      const auto *If = dyn_cast_or_null<IfStmt>(B->getTerminatorStmt());
      if (!If) continue;
      Facts At = In[B->getBlockID()];
      for (const auto &E : *B) if (auto S = E.getAs<CFGStmt>()) transfer(S->getStmt(), At, Escapes.escaped);
      const auto *Term = dyn_cast_or_null<Expr>(B->getTerminatorCondition());
      auto Cond = condition(Term ? Term : If->getCond(), At);
      if (!Cond.call) continue;
      Guards.push_back({B->getBlockID(), 0, Cond.call, Cond.yes});
      Guards.push_back({B->getBlockID(), 1, Cond.call, Cond.no});
    }
    for (const auto *B : *Graph) {
      const auto *Switch = dyn_cast_or_null<SwitchStmt>(B->getTerminatorStmt());
      if (!Switch || !Reachable.count(B->getBlockID())) continue;
      const auto *P = dyn_cast_or_null<ParmVarDecl>(variable(Switch->getCond()));
      if (!P || Escapes.modifiedParameters.count(P->getFunctionScopeIndex())) continue;
      unsigned Position = 0;
      for (auto I = B->succ_begin(); I != B->succ_end(); ++I, ++Position) {
        const auto *To = I->getReachableBlock();
        const auto *Case = To ? dyn_cast_or_null<CaseStmt>(To->getLabel()) : nullptr;
        if (!Case || Case->getRHS()) continue;
        Expr::EvalResult Result;
        if (Case->getLHS()->EvaluateAsInt(Result, C) && Result.Val.getInt().getSignificantBits() < 64)
          Constraints.push_back({B->getBlockID(), Position, P->getFunctionScopeIndex(), Result.Val.getInt().getSExtValue()});
      }
    }
    if (Guards.size() + Constraints.size() > MaxGuards) { unknowns.insert("guard_budget"); return true; }
    std::vector<std::set<unsigned>> Bypass;
    for (const auto &G : Guards) Bypass.push_back(reachable(*Graph, G.branch, G.successor));
    std::vector<std::set<unsigned>> ConstraintBypass;
    for (const auto &K : Constraints) ConstraintBypass.push_back(reachable(*Graph, K.branch, K.successor));
    J::Array Statements, Calls, WriteEffects;
    for (const auto *B : *Graph) {
      if (!Reachable.count(B->getBlockID())) continue;
      unsigned Order = 0;
      for (const auto &E : *B) {
        const unsigned SiteOrder = Order++;
        auto S = E.getAs<CFGStmt>();
        if (!S) continue;
        if (++Sites > MaxSites) { unknowns.insert("site_budget"); return false; }
        const Stmt *Node = S->getStmt();
        Statements.push_back(J::Object{{"kind", Node->getStmtClassName()}, {"block", B->getBlockID()},
          {"span", span(Node->getSourceRange(), C)}, {"guards", obligations(B->getBlockID(), Guards, Bypass, C, Positions)},
          {"constraints", constraints(B->getBlockID(), Constraints, ConstraintBypass)}});
        auto Write = Escapes.writes.find(Node);
        if (Write != Escapes.writes.end() && AccountedWrites.count(Node))
          WriteEffects.push_back(J::Object{{"kind", Write->second}, {"block", B->getBlockID()}, {"order", SiteOrder},
            {"span", span(Node->getSourceRange(), C)}, {"guards", obligations(B->getBlockID(), Guards, Bypass, C, Positions)}});
        if (const auto *Call = dyn_cast<CallExpr>(Node)) {
          J::Value Callee(nullptr), Usr(nullptr);
          if (const auto *Target = Call->getDirectCallee()) {
            Callee = Target->getNameAsString(); Usr = usr(Target);
            const auto Name = Target->getNameAsString();
            if (Name == "commit_creds" || Name == "override_creds" || Name == "revert_creds" ||
                Name == "prepare_kernel_cred" || Name == "set_security_override") Unknown.push_back("credential_context_change");
            if (Target->hasAttr<ReturnsTwiceAttr>() || Name == "longjmp" || Name == "__builtin_longjmp") Unknown.push_back("nonlocal_control_flow");
          }
          else Unknown.push_back("indirect_call");
          Calls.push_back(J::Object{{"callee", std::move(Callee)}, {"callee_usr", std::move(Usr)},
            {"arguments", arguments(Call, C)}, {"span", span(Call->getSourceRange(), C)},
            {"guards", obligations(B->getBlockID(), Guards, Bypass, C, Positions)},
            {"constraints", constraints(B->getBlockID(), Constraints, ConstraintBypass)},
            {"block", B->getBlockID()}, {"order", SiteOrder}});
        }
        if (isa<AsmStmt>(Node)) Unknown.push_back("assembly");
      }
    }
    J::Array Modified;
    for (auto I : Escapes.modifiedParameters) Modified.push_back(I);
    // Only effect ordering needs the adjacency graph. Guard occurrence IDs
    // remain present for every function, including those with no writes.
    if (WriteEffects.empty()) Blocks.clear();
    functions.push_back(J::Object{{"name", F->getNameAsString()}, {"usr", usr(F)},
      {"span", span(F->getSourceRange(), C)}, {"body_span", span(F->getBody()->getSourceRange(), C)}, {"is_static", F->getStorageClass() == SC_Static},
      {"statements", std::move(Statements)}, {"calls", std::move(Calls)}, {"unknowns", std::move(Unknown)},
      {"modified_parameters", std::move(Modified)}, {"write_effects", std::move(WriteEffects)},
      {"write_coverage_complete", WriteCoverageComplete}, {"cfg_blocks", std::move(Blocks)},
      {"declaration_coverage_complete", Translation.complete}, {"body_translation_effects", std::move(TranslationEffects)},
      {"body_metadata_coverage_complete", Translation.metadataComplete}, {"body_metadata_spans", Translation.metadataSpans()},
      {"cfg_entry", Graph->getEntry().getBlockID()}});
    return true;
  }
};

bool dispatchAlias(const ValueDecl *D) {
  return D->hasAttr<AsmLabelAttr>() || D->hasAttr<AliasAttr>() ||
         D->hasAttr<IFuncAttr>() || D->hasAttr<WeakAttr>() || D->hasAttr<WeakRefAttr>();
}

const FunctionDecl *dispatchCallee(const Expr *E, std::string &Reason) {
  if (!E) { Reason = "missing_initializer_slot"; return nullptr; }
  E = E->IgnoreParens();
  if (const auto *Cast = dyn_cast<ImplicitCastExpr>(E)) {
    if (Cast->getCastKind() != CK_FunctionToPointerDecay) {
      Reason = "initializer_cast_not_modeled"; return nullptr;
    }
    E = Cast->getSubExpr()->IgnoreParens();
  }
  if (const auto *Address = dyn_cast<UnaryOperator>(E)) {
    if (Address->getOpcode() != UO_AddrOf) { Reason = "initializer_not_function"; return nullptr; }
    E = Address->getSubExpr()->IgnoreParens();
  }
  const auto *Reference = dyn_cast<DeclRefExpr>(E);
  const auto *Function = Reference ? dyn_cast<FunctionDecl>(Reference->getDecl()) : nullptr;
  if (!Function) { Reason = "initializer_not_function"; return nullptr; }
  for (const auto *Declaration : Function->redecls())
    if (dispatchAlias(Declaration)) { Reason = "callee_alias_not_modeled"; return nullptr; }
  Function = Function->getCanonicalDecl();
  if (Function->getName().empty() || usr(Function).empty()) {
    Reason = "missing_callee_identity"; return nullptr;
  }
  return Function;
}

J::Array syscallTables(ASTContext &C, llvm::StringRef RequestedFile, FunctionVisitor &Visitor) {
  // File identity and target are both necessary: an identically named host
  // fixture, included header, or tracked secondary TU is not an ARM64 table.
  const auto &Target = C.getTargetInfo();
  if (C.getLangOpts().CPlusPlus || Target.getTriple().getArch() != llvm::Triple::aarch64 ||
      !Target.getTriple().isOSLinux() || Target.getPointerWidth(LangAS::Default) != 64 ||
      Target.isBigEndian()) return {};
  auto &SM = C.getSourceManager();
  const std::string File = pathName(RequestedFile, SM);
  const auto MainFile = SM.getFileEntryRefForID(SM.getMainFileID());
  if (!MainFile || pathName(MainFile->getName(), SM) != File) return {};
  const bool Native = llvm::StringRef(File).ends_with("/arch/arm64/kernel/sys.c");
  const bool Compat = llvm::StringRef(File).ends_with("/arch/arm64/kernel/sys32.c");
  if (!Native && !Compat) return {};
  const std::string Name = Native ? "sys_call_table" : "compat_sys_call_table";
  const VarDecl *Table = nullptr;
  for (const auto *D : C.getTranslationUnitDecl()->decls()) {
    const auto *V = dyn_cast<VarDecl>(D);
    if (!V || V->getName() != Name) continue;
    const auto *Definition = V->getDefinition();
    if (Definition && SM.isWrittenInMainFile(SM.getExpansionLoc(Definition->getBeginLoc()))) Table = Definition;
  }
  std::string Reason;
  J::Array Bindings;
  std::set<const FunctionDecl *> Referenced;
  auto Extract = [&]() {
    if (!Table || !Table->isFileVarDecl()) { Reason = "missing_table_definition"; return; }
    if (!Table->hasExternalFormalLinkage()) { Reason = "table_linkage_not_modeled"; return; }
    for (const auto *Declaration : Table->redecls())
      if (dispatchAlias(Declaration)) { Reason = "table_alias_not_modeled"; return; }
    const auto *Array = C.getAsConstantArrayType(Table->getType());
    if (!Array || !Array->getElementType().isConstQualified() ||
        Array->getElementType().isVolatileQualified() || !Array->getElementType()->isFunctionPointerType()) {
      Reason = "table_not_constant_function_pointer_array"; return;
    }
    const auto Count = Array->getSize().getLimitedValue(MaxSyscallSlots + 1);
    if (!Count || Count > MaxSyscallSlots) { Reason = "syscall_slot_budget"; return; }
    const auto *List = dyn_cast_or_null<InitListExpr>(Table->getInit());
    if (List && !List->isSemanticForm()) List = List->getSemanticForm();
    if (!List) { Reason = "initializer_not_semantic_list"; return; }
    for (unsigned I = 0; I < Count; ++I) {
      const Expr *Slot = I < List->getNumInits() ? List->getInit(I) : nullptr;
      if (!Slot) Slot = List->getArrayFiller();
      const auto *Function = dispatchCallee(Slot, Reason);
      if (!Function) return;
      Referenced.insert(Function);
      Bindings.push_back(J::Object{{"number", I}, {"callee_usr", usr(Function)},
                                   {"callee_name", Function->getNameAsString()}});
    }
    Reason = "complete";
  };
  Extract();
  // RecursiveASTVisitor omits InitListExpr's array filler. Explicitly retain
  // every resolved target as an unknown-caller reference, including fillers.
  if (Table) for (const auto *Function : Referenced) {
    if (Visitor.addressTaken.size() >= MaxSites) { Reason = "reference_budget"; break; }
    Visitor.addressTaken.push_back(J::Object{{"name", Function->getNameAsString()}, {"usr", usr(Function)},
      {"span", span(Table->getSourceRange(), C)}});
  }
  if (Reason != "complete") Visitor.unknowns.insert("syscall_table_not_modeled");
  J::Array Tables;
  Tables.push_back(J::Object{{"name", Name}, {"source_path", File},
    {"audit_arch", Native ? 0xC00000B7LL : 0x40000028LL},
    {"complete", Reason == "complete"}, {"status_reason", Reason}, {"bindings", std::move(Bindings)}});
  return Tables;
}

struct Cached {
  std::string key;
  std::unique_ptr<ASTUnit> ast;
  std::set<std::string> dependencies;
  bool preambles = true;
};

struct ByteExclusion {
  std::string path;
  unsigned start, end;
};

struct FingerprintState {
  llvm::SHA256 hash;
  std::vector<ByteExclusion> exclusions;
  std::set<std::string> dependencies;
  size_t tokens = 0, events = 0;
  bool exceeded = false;
  bool expandedOnly = false;
  std::string uncertainty;
  void atom(llvm::StringRef Kind, llvm::StringRef Value) {
    hash.update(Kind); hash.update(":"); hash.update(std::to_string(Value.size()));
    hash.update(":"); hash.update(Value); hash.update(";");
  }
  void location(SourceLocation L, const SourceManager &SM) {
    auto add = [&](llvm::StringRef Kind, SourceLocation At) {
      auto P = SM.getPresumedLoc(At);
      if (!P.isValid()) { exceeded = true; uncertainty = "invalid_source_location"; return; }
      atom(Kind, P.getFilename()); atom("line", std::to_string(P.getLine()));
      atom("column", std::to_string(P.getColumn()));
    };
    add("expansion_location", SM.getExpansionLoc(L));
    add("spelling_location", SM.getSpellingLoc(L));
    unsigned Depth = 0;
    L = SM.getExpansionLoc(L);
    while (L.isValid() && L.isFileID()) {
      L = SM.getIncludeLoc(SM.getFileID(L));
      if (L.isValid()) ++Depth;
    }
    atom("include_depth", std::to_string(Depth));
  }
  void token(const Token &T, Preprocessor &PP, llvm::StringRef Kind) {
    auto Spelling = PP.getSpelling(T);
    atom(Kind, std::to_string(T.getKind())); atom("spelling", Spelling);
    if (Spelling == "__builtin_LINE" || Spelling == "__builtin_COLUMN" ||
        Spelling == "__builtin_FILE" || Spelling == "__builtin_FILE_NAME" ||
        Spelling == "__builtin_FUNCTION" || Spelling == "__builtin_FUNCSIG" ||
        Spelling == "__builtin_source_location") {
      if (PP.getLangOpts().CPlusPlus) {
        // Default arguments can obtain the caller's location, rather than the
        // location of this token. A preprocessor-only action cannot bind it.
        exceeded = true; uncertainty = "cpp_source_location_context_not_modeled";
      } else location(T.getLocation(), PP.getSourceManager());
    }
  }
  bool excluded(SourceLocation L, const SourceManager &SM) const {
    L = SM.getExpansionLoc(L);
    if (L.isInvalid() || !L.isFileID()) return false;
    auto Path = pathName(SM.getFilename(L), SM); auto Offset = SM.getFileOffset(L);
    for (const auto &E : exclusions) if (E.path == Path && E.start <= Offset && Offset < E.end) return true;
    return false;
  }
};

class FingerprintCallbacks : public PPCallbacks {
  Preprocessor &PP;
  FingerprintState &State;
  void event(llvm::StringRef Kind, llvm::StringRef Value) {
    if (++State.events > 1000000) { State.exceeded = true; return; }
    State.atom(Kind, Value);
  }
public:
  FingerprintCallbacks(Preprocessor &PP, FingerprintState &S) : PP(PP), State(S) {}
  void MacroDefined(const Token &Name, const MacroDirective *D) override {
    if (State.expandedOnly) return;
    event("define", PP.getSpelling(Name));
    const auto *M = D->getMacroInfo();
    State.atom("function_like", M->isFunctionLike() ? "1" : "0");
    State.atom("variadic", M->isVariadic() ? "1" : "0");
    for (auto *P : M->params()) State.atom("parameter", P->getName());
    for (const auto &T : M->tokens()) State.token(T, PP, "replacement");
    State.atom("end_define", "");
  }
  void MacroUndefined(const Token &Name, const MacroDefinition &, const MacroDirective *) override {
    if (State.expandedOnly) return;
    event("undef", PP.getSpelling(Name));
  }
  void MacroExpands(const Token &Name, const MacroDefinition &Definition, SourceRange, const MacroArgs *Args) override {
    auto Spelling = PP.getSpelling(Name);
    if (State.expandedOnly && Definition.getMacroInfo() && Definition.getMacroInfo()->isBuiltinMacro() &&
        (Spelling == "__TIME__" || Spelling == "__DATE__" || Spelling == "__TIMESTAMP__")) {
      State.exceeded = true; State.uncertainty = "volatile_preprocessor_builtin_not_pinned:" + Spelling;
      return;
    }
    if (State.expandedOnly) return;
    // Conservative: also retain invocation inputs even inside excluded code.
    // This catches translation effects such as argument-dependent _Pragma.
    event("expand", PP.getSpelling(Name));
    if (Spelling == "__LINE__" || Spelling == "__FILE__" || Spelling == "__FILE_NAME__" ||
        Spelling == "__BASE_FILE__" || Spelling == "__INCLUDE_LEVEL__")
      State.location(Name.getLocation(), PP.getSourceManager());
    if (Args) for (unsigned I = 0; I < Args->getNumMacroArguments(); ++I) {
      State.atom("argument", std::to_string(I));
      for (const Token *T = Args->getUnexpArgument(I); T->isNot(tok::eof); ++T) State.token(*T, PP, "argument_token");
    }
    State.atom("end_expand", "");
  }
  void PragmaDirective(SourceLocation L, PragmaIntroducerKind Introducer) override {
    auto &SM = PP.getSourceManager();
    if (!State.expandedOnly) State.location(L, SM);
    L = SM.getSpellingLoc(L);
    if (Introducer != PIK_HashPragma) {
      State.exceeded = true; State.uncertainty = "pragma_operator_not_modeled"; return;
    }
    if (L.isInvalid() || !L.isFileID()) { State.exceeded = true; return; }
    bool Invalid = false; auto Text = SM.getBufferData(SM.getFileID(L), &Invalid);
    if (Invalid) { State.exceeded = true; return; }
    size_t Start = SM.getFileOffset(L), End = Text.size();
    // Use the real compiler lexer for phase-one/two splices and phase-three
    // comments. A physical newline inside either cannot truncate the pragma.
    Lexer Raw(SM.getLocForStartOfFile(SM.getFileID(L)), PP.getLangOpts(),
              Text.begin(), Text.begin() + Start, Text.end());
    Raw.setParsingPreprocessorDirective(true);
    for (size_t Count = 0;; ++Count) {
      if (Count >= MaxSites) { State.exceeded = true; State.uncertainty = "pragma_token_budget"; return; }
      Token T; Raw.LexFromRawLexer(T);
      if (T.is(tok::eof)) break;
      if (T.is(tok::eod)) { End = SM.getFileOffset(T.getLocation()); break; }
      if (T.is(tok::unknown)) { State.exceeded = true; State.uncertainty = "pragma_lexing_unknown"; return; }
    }
    if (End < Start || End > Text.size()) { State.exceeded = true; return; }
    auto Directive = Text.slice(Start, End);
    event("pragma", Directive);
    // Pragma handlers installed by the real parser can expand arguments that
    // a preprocessor-only frontend does not consume. A macro-bearing pragma
    // can therefore alter later __COUNTER__ branches or Sema state unseen by
    // this action. Do not certify it from its unexpanded spelling alone.
    for (size_t I = 0; I < Directive.size();) {
      if (Directive[I] == '"' || Directive[I] == '\'') {
        char Quote = Directive[I++];
        while (I < Directive.size()) {
          if (Directive[I] == '\\') { I += 2; continue; }
          if (Directive[I++] == Quote) break;
        }
        continue;
      }
      if (!llvm::isAlpha(Directive[I]) && Directive[I] != '_') { ++I; continue; }
      size_t Begin = I++;
      while (I < Directive.size() && (llvm::isAlnum(Directive[I]) || Directive[I] == '_')) ++I;
      if (auto *Name = PP.getIdentifierInfo(Directive.slice(Begin, I)); Name->hasMacroDefinition()) {
        State.exceeded = true; State.uncertainty = "macro_dependent_pragma_not_modeled:" + Name->getName().str();
      }
    }
  }
  void Ident(SourceLocation, llvm::StringRef Text) override {
    if (!State.expandedOnly) event("ident", Text);
  }
  void FileChanged(SourceLocation L, FileChangeReason Reason, SrcMgr::CharacteristicKind, FileID) override {
    auto &SM = PP.getSourceManager();
    if (Reason == EnterFile) {
      L = SM.getExpansionLoc(L);
      if (L.isValid() && L.isFileID()) if (auto File = SM.getFileEntryRefForID(SM.getFileID(L)))
        State.dependencies.insert(pathName(File->getName(), SM));
    } else if (Reason == RenameFile && !State.expandedOnly) {
      auto P = SM.getPresumedLoc(L);
      if (!P.isValid()) { State.exceeded = true; return; }
      event("line_filename", P.getFilename()); State.atom("line_number", std::to_string(P.getLine()));
    }
  }
};

class FingerprintAction : public PreprocessorFrontendAction {
  FingerprintState &State;
public:
  explicit FingerprintAction(FingerprintState &S) : State(S) {}
  void ExecuteAction() override {
    auto &PP = getCompilerInstance().getPreprocessor();
    PP.addPPCallbacks(std::make_unique<FingerprintCallbacks>(PP, State));
    PP.EnterMainSourceFile(); Token T;
    for (;;) {
      PP.Lex(T); if (T.is(tok::eof)) break;
      if (++State.tokens > 2000000 || State.exceeded) { State.exceeded = true; break; }
      if (!State.excluded(T.getLocation(), PP.getSourceManager())) State.token(T, PP, "expanded_token");
    }
  }
};

class FingerprintDiagnostics : public DiagnosticConsumer {
public:
  J::Array errors;
  void HandleDiagnostic(DiagnosticsEngine::Level Level, const Diagnostic &D) override {
    DiagnosticConsumer::HandleDiagnostic(Level, D);
    if (Level >= DiagnosticsEngine::Error) { llvm::SmallString<256> S; D.FormatDiagnostic(S); errors.push_back(std::string(S)); }
  }
};

J::Object fingerprint(const J::Object &Request, std::vector<std::string> Arguments,
                      llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> Real) {
  for (const auto &A : Arguments)
    if (llvm::StringRef(A).starts_with("-include-pch") || llvm::StringRef(A).starts_with("-fmodule") ||
        A == "-fpch-preprocess")
      return J::Object{{"complete", false}, {"diagnostics", J::Array{"precompiled_inputs_not_supported"}}};
  FingerprintState State;
  State.expandedOnly = Request.getString("mode") == std::optional<llvm::StringRef>("pp_expanded");
  if (const auto *Excluded = Request.getArray("excluded_spans")) for (const auto &V : *Excluded) {
    const auto *O = V.getAsObject(); if (!O) return J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_exclusion"}}};
    auto Path = O->getString("path"); auto Start = O->getInteger("start"), End = O->getInteger("end");
    if (!Path || !Start || !End || *Start < 0 || *End < *Start || *End > UINT_MAX)
      return J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_exclusion"}}};
    State.exclusions.push_back({Path->str(), static_cast<unsigned>(*Start), static_cast<unsigned>(*End)});
  }
  auto Memory = llvm::makeIntrusiveRefCnt<llvm::vfs::InMemoryFileSystem>();
  if (const auto *Overlays = Request.getArray("overlays")) for (const auto &V : *Overlays) {
    const auto *O = V.getAsObject(); if (!O) return J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_overlay"}}};
    auto Path = O->getString("path"), Contents = O->getString("contents");
    if (!Path || !Contents) return J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_overlay"}}};
    Memory->addFile(*Path, 0, llvm::MemoryBuffer::getMemBufferCopy(*Contents, *Path));
  }
  auto FS = llvm::makeIntrusiveRefCnt<llvm::vfs::OverlayFileSystem>(Real); FS->pushOverlay(Memory);
  llvm::IntrusiveRefCntPtr<FileManager> Files(new FileManager(FileSystemOptions(), FS));
  FingerprintDiagnostics Diagnostics;
  tooling::ToolInvocation Invocation(std::move(Arguments), std::make_unique<FingerprintAction>(State), Files.get());
  Invocation.setDiagnosticConsumer(&Diagnostics);
  bool Good = Invocation.run() && !State.exceeded && Diagnostics.errors.empty();
  J::Array Dependencies; for (const auto &P : State.dependencies) Dependencies.push_back(P);
  J::Value Digest(nullptr);
  if (Good) Digest = llvm::toHex(State.hash.final(), true);
  if (State.exceeded) Diagnostics.errors.push_back(State.uncertainty.empty() ? "preprocessor_budget_or_unknown" : State.uncertainty);
  return J::Object{{"complete", Good}, {"digest", std::move(Digest)}, {"diagnostics", std::move(Diagnostics.errors)},
                   {"tokens", State.tokens}, {"events", State.events}, {"dependencies", std::move(Dependencies)},
                   {"compiler_major", CLANG_VERSION_MAJOR}, {"compiler_version", getClangFullVersion()}};
}

class Worker {
  std::list<Cached> Cache;
  std::shared_ptr<PCHContainerOperations> PCH = std::make_shared<PCHContainerOperations>();
public:
  J::Object run(const J::Object &Request) {
    if (Request.getString("mode") == std::optional<llvm::StringRef>("version"))
      return J::Object{{"major", CLANG_VERSION_MAJOR}, {"compiler", getClangFullVersion()}};
    auto Directory = Request.getString("directory"), File = Request.getString("file");
    const auto *Args = Request.getArray("arguments");
    if (!Directory || !File || !Args) return J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_request"}}};
    auto FS = llvm::vfs::getRealFileSystem();
    if (auto E = FS->setCurrentWorkingDirectory(*Directory)) return J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_directory"}}};
    std::vector<std::string> Strings;
    for (const auto &A : *Args) { auto S = A.getAsString(); if (!S) return J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_argument"}}}; Strings.push_back(S->str()); }
    std::string Key = Directory->str() + "\n" + File->str();
    for (const auto &S : Strings) Key += "\n" + S;
    if (Request.getString("mode") == std::optional<llvm::StringRef>("pp_fingerprint") ||
        Request.getString("mode") == std::optional<llvm::StringRef>("pp_expanded")) return fingerprint(Request, Strings, FS);
    std::vector<std::pair<std::string, std::string>> OverlaySources;
    if (const auto *Overlays = Request.getArray("overlays")) {
      for (const auto &V : *Overlays) if (const auto *O = V.getAsObject()) {
        auto Path = O->getString("path"), Contents = O->getString("contents");
        if (!Path || !Contents) return J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_overlay"}}};
        OverlaySources.emplace_back(Path->str(), Contents->str());
      }
    }
    auto remaps = [&]() {
      std::vector<ASTUnit::RemappedFile> Result;
      for (const auto &[Path, Contents] : OverlaySources)
        Result.emplace_back(Path, llvm::MemoryBuffer::getMemBufferCopy(Contents, Path).release());
      return Result;
    };
    auto load = [&](unsigned PreambleParses) {
      std::vector<const char *> Argv; for (auto &S : Strings) Argv.push_back(S.c_str());
      auto Opts = std::make_shared<DiagnosticOptions>();
      auto Diags = CompilerInstance::createDiagnostics(*FS, *Opts, new IgnoringDiagConsumer());
      return ASTUnit::LoadFromCommandLine(Argv.data(), Argv.data() + Argv.size(), PCH, Opts, Diags,
          "", false, "", false, CaptureDiagsKind::All, remaps(), true, PreambleParses);
    };
    auto hasErrors = [](ASTUnit *Unit) {
      if (!Unit || Unit->getDiagnostics().hasErrorOccurred()) return true;
      return std::any_of(Unit->stored_diag_begin(), Unit->stored_diag_end(),
                        [](const auto &D) { return D.getLevel() >= DiagnosticsEngine::Error; });
    };
    auto I = std::find_if(Cache.begin(), Cache.end(), [&](const auto &C) { return C.key == Key; });
    bool Reused = I != Cache.end(), Failed = false;
    ASTUnit *AST = nullptr;
    if (Reused) {
      Cache.splice(Cache.begin(), Cache, I); AST = Cache.front().ast.get();
      Failed = AST->Reparse(PCH, remaps(), FS);
    } else {
      auto Result = load(1);
      if (Result) { Cache.push_front({Key, std::move(Result), {}}); AST = Cache.front().ast.get(); }
      else Failed = true;
      while (Cache.size() > 2) Cache.pop_back();
    }
    // Some compiler preambles mishandle __COUNTER__-derived declarations in
    // real kernel headers. Retry the identical inputs once with a fresh full
    // parse. Only an error-free parse replaces the cache; actual compiler
    // errors remain fatal, and this TU then keeps preambles disabled.
    if ((Failed || hasErrors(AST)) && (!AST || Cache.front().preambles)) {
      auto Result = load(0);
      if (!hasErrors(Result.get())) {
        if (AST) Cache.front() = {Key, std::move(Result), {}, false};
        else Cache.push_front({Key, std::move(Result), {}, false});
        AST = Cache.front().ast.get(); Failed = false; Reused = false;
        while (Cache.size() > 2) Cache.pop_back();
      }
    }
    J::Array Diagnostics;
    if (AST) for (auto D = AST->stored_diag_begin(); D != AST->stored_diag_end(); ++D)
      if (D->getLevel() >= DiagnosticsEngine::Error) Diagnostics.push_back(D->getMessage().str());
    if (!AST || Failed || AST->getDiagnostics().hasErrorOccurred() || !Diagnostics.empty())
      return J::Object{{"complete", false}, {"diagnostics", std::move(Diagnostics)}, {"functions", J::Array{}}, {"unknowns", J::Array{"clang_error"}}, {"reused_tu", Reused}};
    std::set<std::string> Paths{File->str()}, Names;
    if (const auto *P = Request.getArray("tracked_paths")) for (const auto &V : *P) if (auto S = V.getAsString()) Paths.insert(S->str());
    if (const auto *N = Request.getArray("function_names")) for (const auto &V : *N) if (auto S = V.getAsString()) Names.insert(S->str());
    FunctionVisitor Visitor(AST->getASTContext(), Paths, Names);
    if (AST->getASTContext().getLangOpts().CPlusPlus) Visitor.unknowns.insert("cxx_not_modeled");
    Visitor.TraverseDecl(AST->getASTContext().getTranslationUnitDecl());
    auto SyscallTables = syscallTables(AST->getASTContext(), *File, Visitor);
    // This audit intentionally ignores requested paths/function filters. Header
    // bodies can contain machine-code or indirect entrances absent from the
    // tracked function CFGs. Completeness means inventory only, never safety.
    EntryClosureVisitor EntryClosure(AST->getASTContext(), Paths, Names);
    if (!EntryClosure.TraverseDecl(AST->getASTContext().getTranslationUnitDecl())) EntryClosure.complete = false;
    auto IndirectTargets = EntryClosure.indirectTargets();
    EmissionVisitor Emission(AST->getASTContext());
    if (!Emission.TraverseDecl(AST->getASTContext().getTranslationUnitDecl())) Emission.complete = false;
    auto EmissionFunctions = Emission.finish(Visitor.addressTaken);
    J::Array Dependencies;
    std::set<std::string> SeenPaths;
    const auto &SM = AST->getSourceManager();
    for (auto I = SM.fileinfo_begin(); I != SM.fileinfo_end(); ++I)
      SeenPaths.insert(pathName(I->first.getName(), SM));
    // SourceManager only materializes some files from a precompiled preamble.
    // Include its serialized inputs too; otherwise a warm reparse can silently
    // lose dependencies that influenced macro/type bindings.
    if (auto Reader = AST->getASTReader()) for (auto &Module : Reader->getModuleManager())
      Reader->visitInputFiles(Module, true, true, [&](const serialization::InputFile &Input, bool) {
        if (auto File = Input.getFile()) SeenPaths.insert(pathName(File->getName(), SM));
        else Visitor.unknowns.insert("missing_preamble_dependency");
        if (Input.isOutOfDate()) Visitor.unknowns.insert("stale_preamble_dependency");
      });
    auto &Saved = Cache.front().dependencies;
    Saved.insert(SeenPaths.begin(), SeenPaths.end());
    if (Saved.size() > 16384) Visitor.unknowns.insert("dependency_budget");
    for (const auto &Path : Saved) Dependencies.push_back(Path);
    if (AST->getDiagnostics().hasErrorOccurred()) Visitor.unknowns.insert("deferred_clang_error");
    J::Array Unknown; for (const auto &S : Visitor.unknowns) Unknown.push_back(S);
    return J::Object{{"complete", Visitor.unknowns.empty()}, {"diagnostics", std::move(Diagnostics)},
            {"functions", std::move(Visitor.functions)}, {"unknowns", std::move(Unknown)}, {"reused_tu", Reused},
            {"fresh_parse_fallback", !Cache.front().preambles},
            {"dependencies", std::move(Dependencies)}, {"address_taken", std::move(Visitor.addressTaken)},
            {"file_scope_assembly", std::move(Visitor.fileAssembly)},
            {"syscall_tables", std::move(SyscallTables)},
            {"inline_assembly_coverage_complete", EntryClosure.complete},
            {"inline_assembly", std::move(EntryClosure.inlineAssembly)},
            {"indirect_call_coverage_complete", EntryClosure.complete},
            {"indirect_calls", std::move(EntryClosure.indirectCalls)},
            {"indirect_target_coverage_complete", EntryClosure.complete && EntryClosure.targetCoverageComplete},
            {"indirect_call_targets", std::move(IndirectTargets)},
            {"target_architecture", AST->getASTContext().getTargetInfo().getTriple().getArchName()},
            {"emission_coverage_complete", Emission.complete && Names.empty()},
            {"emission_functions", std::move(EmissionFunctions)},
            {"compiler_major", CLANG_VERSION_MAJOR}, {"compiler_version", getClangFullVersion()}};
  }
};
} // namespace

int main() {
  Worker W; std::string Line;
  while (std::getline(std::cin, Line)) {
    if (Line.size() > 8 * 1024 * 1024) { std::cout << "{\"complete\":false,\"diagnostics\":[\"request_budget\"]}\n" << std::flush; continue; }
    auto Parsed = J::parse(Line);
    J::Object Out;
    if (!Parsed) { llvm::consumeError(Parsed.takeError()); Out = J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_json"}}}; }
    else if (const auto *R = Parsed->getAsObject()) Out = W.run(*R);
    else Out = J::Object{{"complete", false}, {"diagnostics", J::Array{"invalid_request"}}};
    std::string Encoded; llvm::raw_string_ostream Stream(Encoded); Stream << J::Value(std::move(Out));
    std::cout << Encoded << '\n' << std::flush;
  }
}
