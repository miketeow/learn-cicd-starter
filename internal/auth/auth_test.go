package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		want          string
		wantErrString string
	}{
		{
			name:    "No Authorization Header",
			headers: http.Header{},
			want:    "",
			wantErrString: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "Correct Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-key"},
			},
			want:    "my-secret-key",
			wantErrString: "",
		},
		{
			name: "Malformed Header - No Space",
			headers: http.Header{
				"Authorization": []string{"ApiKeymy-secret-key"},
			},
			want:    "",
			wantErrString: "malformed authorization header",
		},
		{
			name: "Wrong Prefix - Bearer",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-key"},
			},
			want:    "",
			wantErrString: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			// Check error expectations
			if tt.wantErrString != "" {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, wantErr %v", tt.wantErrString)
					return
				}
				if err.Error() != tt.wantErrString {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErrString)
					return
				}
			} else if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
				return
			}

			// Check value expectation
			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
