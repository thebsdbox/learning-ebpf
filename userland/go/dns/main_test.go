package main

import (
	"reflect"
	"testing"
)

func TestConvertDomain(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "working 3 part",
			args: args{
				name: "bbc.co.uk",
			},
			want: []byte{03, 'b', 'b', 'c', 2, 'c', 'o', 2, 'u', 'k'},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConvertDomain(tt.args.name); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConvertDomain() = %v, want %v", got, tt.want)
			}
		})
	}
}
