set_field!(BabyBear);
define_buffer_list! {
all: [accum,code,data,global,mix,test,],
rows: [accum,code,data,test,],
taps: [accum,code,data,],
globals: [global,mix,],}
define_tap_buffer! {accum,  103,  0}
define_tap_buffer! {code,  1,  1}
define_tap_buffer! {data,  211,  2}
define_global_buffer! {global,  90}
define_global_buffer! {mix,  36}
define_buffer! {test,  211}
