(** Minimal signature for hashtables. *)

module Make (Domain: Hashtbl.HashedType) =
struct
  module H = Hashtbl.Make(Domain)
  type key = Domain.t
  type 'a t = 'a H.t * 'a

  let create size def = (H.create size, def)
  let find (map,def) key = try H.find map key with Not_found -> def
  let find_all (map,def) key = H.find_all map key @ [def]
  let find_default (map,_) key def = try H.find map key with Not_found -> def
  let copy (map,def) = (H.copy map, def)  (* NB! maybe default should be copied? *)

  (* and this is inheritance???   *)
  let lift f (map,_) = f map
  let clear x = lift H.clear x
  let add x k = lift H.add x k
  let remove x = lift H.remove x
  let replace x =  lift H.replace x
  let mem x = lift H.mem x (* or const true??? *)
  let iter f = lift (H.iter f)
  let fold f = lift (H.fold f)
  let length x = lift H.length x
end

module type S =
sig
  type key
  type 'a t
  val create: int -> 'a -> 'a t
  val clear: 'a t -> unit
  val copy: 'a t -> 'a t
  val add: 'a t -> key -> 'a -> unit
  val remove: 'a t -> key -> unit
  val find: 'a t -> key -> 'a
  val find_all: 'a t -> key -> 'a list
  val replace : 'a t -> key -> 'a -> unit
  val mem : 'a t -> key -> bool
  val iter: (key -> 'a -> unit) -> 'a t -> unit
  val fold: (key -> 'a -> 'b -> 'b) -> 'a t -> 'b -> 'b
  val length: 'a t -> int
end

module type H =
sig
  type key
  type 'a t
  val create: int -> 'a t
  val clear: 'a t -> unit
  val copy: 'a t -> 'a t
  val add: 'a t -> key -> 'a -> unit
  val remove: 'a t -> key -> unit
  val find: 'a t -> key -> 'a
  val find_default: 'a t -> key -> 'a -> 'a
  val find_all: 'a t -> key -> 'a list
  val replace : 'a t -> key -> 'a -> unit
  val mem : 'a t -> key -> bool
  val iter: (key -> 'a -> unit) -> 'a t -> unit
  val fold: (key -> 'a -> 'b -> 'b) -> 'a t -> 'b -> 'b
  val length: 'a t -> int
end

module type SP =
sig
  include Printable.S
  type key
  type value
  val create: int -> t
  val clear: t -> unit
  val copy: t -> t
  val add: t -> key -> value -> unit
  val remove: t -> key -> unit
  val find: t -> key -> value
  val find_all: t -> key -> value list
  val replace : t -> key -> value -> unit
  val mem : t -> key -> bool
  val iter: (key -> value -> unit) -> t -> unit
  val fold: (key -> value -> 'b -> 'b) -> t -> 'b -> 'b
  val length: t -> int
end

module Printable (Domain: Printable.S) (Range: Printable.S) =
struct
  include Printable.Std
  module M = Hashtbl.Make (Domain)
  (* How can I just include this one and set the type 'a t = Range.t M.t???
   * I will just include them manually for now! *)
  type t = Range.t M.t
  type key = Domain.t
  type value = Range.t
  let create = M.create
  let clear = M.clear
  let find = M.find
  let find_all = M.find_all
  let copy = M.copy
  let add = M.add
  let remove = M.remove
  let replace = M.replace
  let mem = M.mem
  let iter = M.iter
  let fold = M.fold
  let length = M.length

  let equal x y =
    let forall2 f x y =
      let ch k v t = t && try f (find x k) v with Not_found -> false in
      fold ch y true
    in length x = length y && forall2 Range.equal x y
  let hash xs = fold (fun k v xs -> xs lxor (Domain.hash k) lxor (Range.hash v)) xs 0
  let show x = "mapping"


  open Pretty
  let pretty () mapping =
    let f key st dok =
      dok ++ dprintf "%a ->@?  @[%a@]\n" Domain.pretty key Range.pretty st
    in
    let content () = fold f mapping nil in
    let defline () = dprintf "OTHERS -> Not available\n" in
    dprintf "@[Mapping {\n  @[%t%t@]}@]" content defline

  let printXml f xs =
    let print_one k v =
      BatPrintf.fprintf f "<key>\n%a</key>\n%a" Domain.printXml k Range.printXml v
    in
    BatPrintf.fprintf f "<value>\n<set>\n";
    iter print_one xs;
    BatPrintf.fprintf f "</set>\n</value>\n"
end
