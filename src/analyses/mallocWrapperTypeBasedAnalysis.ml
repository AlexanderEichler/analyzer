(** An analysis that handles the case when malloc is called from a wrapper function all over the code. *)

open Prelude.Ana
open Analyses
let prefix_non_definite_mem = Lval.prefix_non_definite_mem

module Spec : Analyses.Spec =
struct
  include Analyses.DefaultSpec

  module F = Lattice.Unit

  let name () = "mallocWrapperTypeBased"
  module D = F
  module G = Lattice.Unit
  module C = D

  module Q = Queries

  (* transfer functions *)
  let assign ctx (lval:lval) (rval:exp) : D.t = ()

  let branch ctx (exp:exp) (tv:bool) : D.t = ()

  let body ctx (f:fundec) : D.t = ()

  let return ctx (exp:exp option) (f:fundec) : D.t = ()

  let enter ctx (lval: lval option) (f:varinfo) (args:exp list) : (D.t * D.t) list =
    let calleectx = () in
    [(ctx.local, calleectx)]

  let combine ctx (lval:lval option) fexp (f:varinfo) (args:exp list) fc (au:D.t) : D.t = ()

  let special ctx (lval: lval option) (f:varinfo) (arglist:exp list) : D.t = ()

  let startstate v = D.bot ()
  let threadenter ctx lval f args = D.top ()
  let threadspawn ctx lval f args fctx = D.bot ()
  let exitstate  v = D.top ()

  let heap_hash = Hashtbl.create 113
  let heap_vars = Hashtbl.create 113
  let arg_hash = Hashtbl.create 113


  let get_heap_var (ts : typsig) (fn : varinfo) =
    try Hashtbl.find heap_hash (ts, fn)
    with Not_found ->
      let tsname = Pretty.sprint ~width:80 (d_typsig () ts) in
      (* "nd" for "not definite" - this does not refer to one particular memory block *)
      let name = prefix_non_definite_mem ^ "@" ^ fn.vname ^ ":" ^ tsname ^ ")" in
      let newvar = Goblintutil.create_var (makeGlobalVar name voidType) in
      Hashtbl.add heap_hash (ts, fn) newvar;
      Hashtbl.add heap_vars newvar.vid ();
      newvar

  let get_arg_var (ts : typsig) =
    try Hashtbl.find arg_hash ts
    with Not_found ->
      let tsname = Pretty.sprint ~width:80 (d_typsig () ts) in
      (* "nd" for "not definite" *)
      let name = prefix_non_definite_mem ^ ":" ^ tsname ^ ")" in
      let newvar = Goblintutil.create_var (makeGlobalVar name voidType) in
      Hashtbl.add arg_hash ts newvar;
      Hashtbl.add heap_vars newvar.vid ();
      newvar

  let query ctx (q:Q.t) : Q.Result.t =
    match q with
    | Q.ArgVarTyp t ->
      let ts = typeSig t in
      `Varinfo (`Lifted (get_arg_var ts))
    | Q.HeapVar ->
      let fn = (MyCFG.getFun ctx.node).svar in
      let rval =
        match ctx.node with
          | Node.Statement s -> (match s.skind with
            Instr [i] -> (match i with
              | Set (_,e,_) -> Some e
              | _ -> None)
            | _ -> None)
          | _ -> None
      in
      let ts = (match rval with
        | Some e -> typeSig (typeOf e)
        | _ -> typeSig (TVoid []))
      in
      `Varinfo (`Lifted (get_heap_var ts fn))
    | Q.IsHeapVar v ->
      `MayBool (Hashtbl.mem heap_vars v.vid)
    | _ -> `Top

    let init () =
      Hashtbl.clear heap_hash;
      Hashtbl.clear heap_vars
end

let _ =
  MCP.register_analysis (module Spec : Spec)
