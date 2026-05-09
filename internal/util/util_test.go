// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package util

import "testing"

func TestSlicesEqual(t *testing.T) {
	tests := []struct {
		name string
		s1   []string
		s2   []string
		want bool
	}{
		{
			name: "same order",
			s1:   []string{"read", "write"},
			s2:   []string{"read", "write"},
			want: true,
		},
		{
			name: "different order",
			s1:   []string{"read", "write"},
			s2:   []string{"write", "read"},
			want: true,
		},
		{
			name: "different lengths",
			s1:   []string{"read"},
			s2:   []string{"read", "write"},
			want: false,
		},
		{
			name: "same length different values",
			s1:   []string{"read", "write"},
			s2:   []string{"read", "delete"},
			want: false,
		},
		{
			name: "same length different multiplicity",
			s1:   []string{"read", "write"},
			s2:   []string{"read", "read"},
			want: false,
		},
		{
			name: "same multiplicity",
			s1:   []string{"read", "read", "write"},
			s2:   []string{"write", "read", "read"},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SlicesEqual(tt.s1, tt.s2); got != tt.want {
				t.Fatalf("SlicesEqual(%v, %v) = %v, want %v", tt.s1, tt.s2, got, tt.want)
			}
		})
	}
}
