module D : RelationalIntDomainSignature.S =
struct
  type t = unit

  let raise_error = raise (Invalid_argument "In order to use the apron domain, please install apron and build goblint using 'make poly'")
  let equal _ _ =  raise_error
  let hash _ = raise_error
  let compare _ _ = raise_error
  let short _ _ = raise_error
  let isSimple _ = raise_error
  let pretty = raise_error
  let pretty_diff _ _ = raise_error
  let toXML = raise_error
  let pretty_f _ _ _  = raise_error
  let toXML_f _ _  = raise_error
  let printXml _ _  = raise_error
  let name = raise_error
  let leq _ _  = raise_error
  let join _ _  = raise_error
  let meet _ _  = raise_error
  let widen _ _ = raise_error
  let narrow _ _ = raise_error
  let bot _ = raise_error
  let top  _ = raise_error
  let is_bot _ = raise_error
  let is_top _ = raise_error
  let add_variable_value_list _ _ = raise_error
  let add_variable_value_pair _ _ = raise_error
  let eval_assign_cil_exp _ _ = raise_error
  let eval_assert_cil_exp _ _ = raise_error
  let eval_assign_int_value _ _ = raise_error
  let get_value_of_variable _ _ = raise_error
  let meet_local_and_global_state _ _ = raise_error
  let remove_all_top_variables _ = raise_error
  let remove_all_local_variables _ = raise_error
  let remove_variable _ _ = raise_error
end
